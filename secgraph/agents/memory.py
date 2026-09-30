"""Shared memory for agents and analysts — the graph's "second brain".

Agents working different cases see the same graph, so what one learns can be
recalled by the next: an observation about a host, the decision taken on an
alert, a lesson that a playbook worked. Notes are tied to graph entities and
carry a *signature* (features of the situation). ``suggest`` finds notes whose
signature resembles the current situation and ranks them by how often they
helped, so a proven approach from one investigation surfaces in another.

Notes are free text written by agents, so they are treated as untrusted data:
secrets are redacted on write, sizes are bounded, the protective plane can veto
a write, and consumers receive notes clearly delimited as reference material.
"""

from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import NotFound, ValidationFailed
from secgraph.governance.guardrail import Guardrail, redact_secrets
from secgraph.governance.rbac import AccessScope, Principal
from secgraph.observability import MEMORY_NOTES, get_logger
from secgraph.ontology.model import Ontology
from secgraph.store.db import Database
from secgraph.store.models import MemoryLink, MemoryNote, MemoryTerm, Node
from secgraph.store.repository import GraphReader, chunked
from secgraph.store.types import utcnow

log = get_logger(__name__)

KINDS = ("observation", "decision", "lesson", "playbook", "hypothesis")
OUTCOMES = ("used", "success", "failure")
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]{1,63}")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.:/-]{0,47}$")
_FEATURE_RE = re.compile(r"^[a-z0-9_]{1,24}:[^\s]{1,64}$")
_STOPWORD_TEXT = (
    "a an and are as at be been but by can did do does for from had has have he her his how i if in into is it its "
    "may me my no not of on or our she should so than that the their them then there these they this to too very was "
    "we were what when where which while who why will with would you your"
)
_STOPWORDS = frozenset(_STOPWORD_TEXT.split())
_MAX_TERMS = 400
_MAX_LINKS = 50
_EXTRA_FEATURE_PENALTY = 0.25  # how much a note's specifics that the situation lacks count against it
_BM25_K1 = 1.5
_BM25_B = 0.75
# Per node type: properties that characterise "what kind of situation this is".
_SIGNATURE_PROPERTIES: dict[str, tuple[str, ...]] = {
    "Asset": ("asset_type", "environment"),
    "Alert": ("rule", "severity"),
    "Finding": ("severity",),
    "Control": ("control_type",),
    "Identity": ("identity_type",),
    "DataStore": ("store_type", "classification"),
    "AIAgent": ("autonomy_level",),
    "NetworkSegment": ("zone",),
}
# Per node type: (identifier kind, feature name) — well-known ids that make situations comparable.
_SIGNATURE_IDENTIFIERS: dict[str, tuple[str, str]] = {
    "Technique": ("attack_id", "technique"),
    "Vulnerability": ("cve", "cve"),
}


def tokenize(text: str) -> list[str]:
    tokens = []
    for token in _TOKEN_RE.findall(text.lower()):
        token = token.strip(".:/-_")
        if len(token) >= 2 and token not in _STOPWORDS:
            tokens.append(token[:64])
    return tokens


def wilson_lower_bound(successes: int, trials: int, z: float = 1.96) -> float:
    """Lower end of the 95% confidence interval for a success rate — cautious with little evidence."""
    if trials <= 0:
        return 0.0
    phat = successes / trials
    denominator = 1 + z * z / trials
    centre = phat + z * z / (2 * trials)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * trials)) / trials)
    return max(0.0, (centre - margin) / denominator)


class MemoryService:
    def __init__(self, db: Database, ontology: Ontology, settings: Settings, guardrail: Guardrail):
        self.db = db
        self.ontology = ontology
        self.settings = settings
        self.guardrail = guardrail

    # ------------------------------------------------------------------ #
    # Signatures
    # ------------------------------------------------------------------ #
    def features_for(self, session: Session, tenant_id: str, node_ids: list[str]) -> list[str]:
        """Situation features derived from entities: their types, key attributes and well-known ids."""
        if not node_ids:
            return []
        reader = GraphReader(session, tenant_id)
        records = reader.get_nodes(node_ids)
        identifiers = reader.identifiers_for([i for i, r in records.items() if r.type in _SIGNATURE_IDENTIFIERS])
        features: list[str] = []
        for node_id, record in records.items():
            features.append(f"type:{record.type.lower()}")
            for prop in _SIGNATURE_PROPERTIES.get(record.type, ()):
                value = record.properties.get(prop)
                if isinstance(value, str | int | bool) and str(value).strip():
                    features.append(f"{prop}:{str(value).strip().lower()[:64]}".replace(" ", "_"))
            known = _SIGNATURE_IDENTIFIERS.get(record.type)
            if known:
                kind, feature = known
                for value in identifiers.get(node_id, {}).get(kind, [])[:1]:
                    features.append(f"{feature}:{value.lower()}")
        return sorted(set(features))

    @staticmethod
    def _clean_features(features: list[str] | None) -> list[str]:
        cleaned = []
        for feature in features or []:
            if not isinstance(feature, str):
                raise ValidationFailed("signature features must be strings")
            feature = feature.strip().lower().replace(" ", "_")
            if not _FEATURE_RE.match(feature):
                raise ValidationFailed(f"signature feature {feature!r} must look like 'name:value'")
            cleaned.append(feature)
        if len(cleaned) > 64:
            raise ValidationFailed("at most 64 signature features")
        return sorted(set(cleaned))

    @staticmethod
    def _clean_tags(tags: list[str] | None) -> list[str]:
        cleaned = []
        for tag in tags or []:
            if not isinstance(tag, str) or not _TAG_RE.match(tag.strip().lower()):
                raise ValidationFailed(f"tag {tag!r} must be 1-48 characters of a-z, 0-9 and _ . : / -")
            cleaned.append(tag.strip().lower())
        if len(cleaned) > 32:
            raise ValidationFailed("at most 32 tags")
        return sorted(set(cleaned))

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    def remember(
        self,
        tenant_id: str,
        principal: Principal,
        *,
        kind: str,
        title: str,
        body: str = "",
        entity_ids: list[str] | None = None,
        tags: list[str] | None = None,
        signature: list[str] | None = None,
        confidence: float | None = None,
        supersedes: str | None = None,
        ttl_days: int | None = None,
    ) -> dict[str, Any]:
        if kind not in KINDS:
            raise ValidationFailed(f"kind must be one of {', '.join(KINDS)}")
        title = (title or "").strip()
        body = body or ""
        if not 3 <= len(title) <= 256:
            raise ValidationFailed("title must be 3-256 characters")
        if len(body) > self.settings.memory_max_body_chars:
            raise ValidationFailed(f"body is limited to {self.settings.memory_max_body_chars} characters")
        if confidence is not None and not 0.0 <= confidence <= 1.0:
            raise ValidationFailed("confidence must be within [0, 1]")
        if ttl_days is not None and not 1 <= ttl_days <= 3650:
            raise ValidationFailed("ttl_days must be between 1 and 3650")
        entity_ids = list(dict.fromkeys(entity_ids or []))
        if len(entity_ids) > _MAX_LINKS:
            raise ValidationFailed(f"a note can link at most {_MAX_LINKS} entities")
        clean_tags = self._clean_tags(tags)
        extra_features = self._clean_features(signature)

        title, found_title = redact_secrets(title)
        body, found_body = redact_secrets(body)
        redactions = sorted(set(found_title + found_body))
        verdict = self.guardrail.check(
            "memory.write",
            {"kind": kind, "title": title, "body": body, "tags": clean_tags},
            {"tenant": tenant_id, "principal": principal.id, "principal_kind": principal.kind},
        )
        title = str(verdict.get("title", title))[:256]
        body = str(verdict.get("body", body))[: self.settings.memory_max_body_chars]
        note_id = uuid.uuid4().hex
        now = utcnow()
        scope = principal.scope

        def _work(session: Session) -> dict[str, Any]:
            reader = GraphReader(session, tenant_id)
            resolved = [reader.resolve_id(i) for i in entity_ids]
            records = reader.get_nodes(resolved)
            for original, node_id in zip(entity_ids, resolved, strict=True):
                record = records.get(node_id)
                if record is None or not scope.allows(record.type):
                    raise NotFound(f"node {original} does not exist")
            features = sorted(set(self.features_for(session, tenant_id, resolved)) | set(extra_features))
            tokens = tokenize(f"{title}\n{body}\n{' '.join(clean_tags)}")
            if supersedes:
                previous = session.execute(
                    select(MemoryNote).where(MemoryNote.tenant_id == tenant_id, MemoryNote.id == supersedes)
                ).scalar_one_or_none()
                if previous is None:
                    raise NotFound(f"note {supersedes} does not exist")
                previous.status = "archived"
                previous.updated_at = now
            note = MemoryNote(
                id=note_id,
                tenant_id=tenant_id,
                kind=kind,
                title=title,
                body=body,
                tags=clean_tags,
                signature=features,
                author=principal.id,
                author_kind=principal.kind,
                confidence=confidence if confidence is not None else 0.5,
                token_count=len(tokens),
                supersedes=supersedes,
                created_at=now,
                updated_at=now,
                expires_at=now + timedelta(days=ttl_days) if ttl_days else None,
            )
            session.add(note)
            session.add_all(MemoryLink(tenant_id=tenant_id, note_id=note_id, node_id=i) for i in set(resolved))
            counts = Counter(tokens)
            terms = [(f"w:{term}", tf) for term, tf in counts.most_common(_MAX_TERMS)]
            terms += [(f"f:{feature}", 1) for feature in features]
            terms += [(f"f:tag:{tag}", 1) for tag in clean_tags]
            session.add_all(
                MemoryTerm(tenant_id=tenant_id, term=term[:96], note_id=note_id, tf=tf)
                for term, tf in dict(terms).items()
            )
            session.flush()
            return self._view(note, sorted(set(resolved)))

        view = self.db.run(_work)
        MEMORY_NOTES.labels(kind=kind).inc()
        if redactions:
            view["redacted"] = redactions
            log.warning("secrets redacted from memory note", note_id=note_id, kinds=redactions)
        return view

    def feedback(self, tenant_id: str, principal: Principal, note_id: str, outcome: str) -> dict[str, Any]:
        """Record that a note was used, and whether acting on it worked."""
        if outcome not in OUTCOMES:
            raise ValidationFailed(f"outcome must be one of {', '.join(OUTCOMES)}")

        def _work(session: Session) -> dict[str, Any]:
            note = session.execute(
                select(MemoryNote).where(MemoryNote.tenant_id == tenant_id, MemoryNote.id == note_id).with_for_update()
            ).scalar_one_or_none()
            if note is None:
                raise NotFound(f"note {note_id} does not exist")
            note.uses += 1
            if outcome == "success":
                note.successes += 1
            elif outcome == "failure":
                note.failures += 1
            note.updated_at = utcnow()
            return self._view(note, self._links(session, tenant_id, [note_id]).get(note_id, []))

        return self.db.run(_work)

    def archive(self, tenant_id: str, principal: Principal, note_id: str) -> None:
        def _work(session: Session) -> None:
            note = session.execute(
                select(MemoryNote).where(MemoryNote.tenant_id == tenant_id, MemoryNote.id == note_id)
            ).scalar_one_or_none()
            if note is None:
                raise NotFound(f"note {note_id} does not exist")
            note.status = "archived"
            note.updated_at = utcnow()
            session.execute(delete(MemoryTerm).where(MemoryTerm.tenant_id == tenant_id, MemoryTerm.note_id == note_id))

        self.db.run(_work)

    def expire(self, tenant_id: str) -> int:
        """Archive notes past their ``expires_at`` (maintenance worker)."""

        def _work(session: Session) -> int:
            now = utcnow()
            ids = list(
                session.execute(
                    select(MemoryNote.id).where(
                        MemoryNote.tenant_id == tenant_id,
                        MemoryNote.status == "active",
                        MemoryNote.expires_at.is_not(None),
                        MemoryNote.expires_at < now,
                    )
                ).scalars()
            )
            for chunk in chunked(ids):
                for note in session.execute(select(MemoryNote).where(MemoryNote.id.in_(chunk))).scalars():
                    note.status = "archived"
                    note.updated_at = now
                session.execute(
                    delete(MemoryTerm).where(MemoryTerm.tenant_id == tenant_id, MemoryTerm.note_id.in_(chunk))
                )
            return len(ids)

        return self.db.run(_work)

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def _links(self, session: Session, tenant_id: str, note_ids: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for chunk in chunked(note_ids):
            rows = session.execute(
                select(MemoryLink.note_id, MemoryLink.node_id).where(
                    MemoryLink.tenant_id == tenant_id, MemoryLink.note_id.in_(chunk)
                )
            )
            for note_id, node_id in rows:
                out.setdefault(note_id, []).append(node_id)
        return out

    def _visible(
        self, session: Session, tenant_id: str, scope: AccessScope, links: dict[str, list[str]], note_ids: list[str]
    ) -> set[str]:
        """A type-restricted caller sees a note only if every entity it links is visible to them."""
        if scope.unrestricted:
            return set(note_ids)
        node_ids = sorted({n for ids in links.values() for n in ids})
        types: dict[str, str] = {}
        for chunk in chunked(node_ids):
            for node_id, node_type in session.execute(
                select(Node.id, Node.type).where(Node.tenant_id == tenant_id, Node.id.in_(chunk))
            ):
                types[node_id] = node_type
        return {note_id for note_id in note_ids if all(scope.allows(types.get(n, "")) for n in links.get(note_id, []))}

    @staticmethod
    def _view(note: MemoryNote, entity_ids: list[str]) -> dict[str, Any]:
        return {
            "id": note.id,
            "kind": note.kind,
            "title": note.title,
            "body": note.body,
            "tags": list(note.tags or []),
            "signature": list(note.signature or []),
            "entity_ids": sorted(entity_ids),
            "author": note.author,
            "author_kind": note.author_kind,
            "confidence": note.confidence,
            "status": note.status,
            "uses": note.uses,
            "successes": note.successes,
            "failures": note.failures,
            "success_score": round(wilson_lower_bound(note.successes, note.successes + note.failures), 4),
            "supersedes": note.supersedes,
            "created_at": note.created_at.isoformat(),
            "updated_at": note.updated_at.isoformat(),
            "expires_at": note.expires_at.isoformat() if note.expires_at else None,
        }

    def get(self, tenant_id: str, scope: AccessScope, note_id: str) -> dict[str, Any]:
        with self.db.transaction() as session:
            note = session.execute(
                select(MemoryNote).where(MemoryNote.tenant_id == tenant_id, MemoryNote.id == note_id)
            ).scalar_one_or_none()
            links = self._links(session, tenant_id, [note_id])
            if note is None or note_id not in self._visible(session, tenant_id, scope, links, [note_id]):
                raise NotFound(f"note {note_id} does not exist")
            return self._view(note, links.get(note_id, []))

    def _bm25(
        self, session: Session, tenant_id: str, terms: list[str], limit_postings: int = 20000
    ) -> dict[str, float]:
        """Okapi BM25 over the inverted index, computed in the application for portability."""
        terms = list(dict.fromkeys(terms))[:64]
        if not terms:
            return {}
        total = session.execute(
            select(func.count())
            .select_from(MemoryNote)
            .where(MemoryNote.tenant_id == tenant_id, MemoryNote.status == "active")
        ).scalar_one()
        if not total:
            return {}
        average: float = float(
            session.execute(
                select(func.avg(MemoryNote.token_count)).where(
                    MemoryNote.tenant_id == tenant_id, MemoryNote.status == "active"
                )
            ).scalar_one()
            or 1.0
        )
        average = max(float(average), 1.0)
        postings = session.execute(
            select(MemoryTerm.term, MemoryTerm.note_id, MemoryTerm.tf)
            .where(MemoryTerm.tenant_id == tenant_id, MemoryTerm.term.in_(terms))
            .limit(limit_postings)
        ).all()
        document_frequency = Counter(term for term, _note, _tf in postings)
        note_ids = sorted({note for _term, note, _tf in postings})
        lengths: dict[str, int] = {}
        for chunk in chunked(note_ids):
            for note_id, count in session.execute(
                select(MemoryNote.id, MemoryNote.token_count).where(
                    MemoryNote.id.in_(chunk), MemoryNote.status == "active"
                )
            ):
                lengths[note_id] = max(int(count), 1)
        scores: dict[str, float] = {}
        for term, note_id, tf in postings:
            if note_id not in lengths:
                continue
            df = document_frequency[term]
            idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
            norm = tf * (_BM25_K1 + 1) / (tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * lengths[note_id] / average))
            scores[note_id] = scores.get(note_id, 0.0) + idf * norm
        return scores

    def _feature_weights(self, session: Session, tenant_id: str, features: set[str]) -> dict[str, float]:
        """Inverse document frequency of each signature feature across active notes."""
        total = session.execute(
            select(func.count())
            .select_from(MemoryNote)
            .where(MemoryNote.tenant_id == tenant_id, MemoryNote.status == "active")
        ).scalar_one()
        frequency: dict[str, int] = {}
        ordered = sorted(features)
        for chunk in chunked(ordered):
            rows = session.execute(
                select(MemoryTerm.term, func.count())
                .where(MemoryTerm.tenant_id == tenant_id, MemoryTerm.term.in_([f"f:{f}" for f in chunk]))
                .group_by(MemoryTerm.term)
            )
            for term, count in rows:
                frequency[term[2:]] = int(count)
        return {
            f: math.log(1 + (total - min(frequency.get(f, 0), total) + 0.5) / (frequency.get(f, 0) + 0.5))
            for f in ordered
        }

    def search(
        self,
        tenant_id: str,
        scope: AccessScope,
        *,
        query: str | None = None,
        entity_id: str | None = None,
        kind: str | None = None,
        tags: list[str] | None = None,
        include_archived: bool = False,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if kind is not None and kind not in KINDS:
            raise ValidationFailed(f"kind must be one of {', '.join(KINDS)}")
        if query is not None and len(query) > 1000:
            raise ValidationFailed("query is limited to 1000 characters")
        limit = max(1, min(limit, 100))
        wanted_tags = self._clean_tags(tags)
        with self.db.transaction() as session:
            scores: dict[str, float] | None = None
            if query and query.strip():
                scores = self._bm25(session, tenant_id, [f"w:{t}" for t in tokenize(query)])
                if not scores:
                    return []
            conditions = [MemoryNote.tenant_id == tenant_id]
            if not include_archived:
                conditions.append(MemoryNote.status == "active")
                conditions.append(or_(MemoryNote.expires_at.is_(None), MemoryNote.expires_at > utcnow()))
            if kind:
                conditions.append(MemoryNote.kind == kind)
            stmt = select(MemoryNote).where(*conditions)
            if entity_id:
                resolved = GraphReader(session, tenant_id).resolve_id(entity_id)
                stmt = stmt.where(
                    MemoryNote.id.in_(
                        select(MemoryLink.note_id).where(
                            MemoryLink.tenant_id == tenant_id, MemoryLink.node_id == resolved
                        )
                    )
                )
            if scores is not None:
                best = sorted(scores, key=lambda i: -scores[i])[:500]
                stmt = stmt.where(MemoryNote.id.in_(best))
            notes = list(session.execute(stmt.order_by(MemoryNote.updated_at.desc()).limit(500)).scalars())
            if wanted_tags:
                notes = [n for n in notes if set(wanted_tags) <= set(n.tags or [])]
            ids = [n.id for n in notes]
            links = self._links(session, tenant_id, ids)
            visible = self._visible(session, tenant_id, scope, links, ids)
            notes = [n for n in notes if n.id in visible]
            if scores is not None:
                notes.sort(key=lambda n: (-scores.get(n.id, 0.0), n.id))
            out = []
            for note in notes[:limit]:
                view = self._view(note, links.get(note.id, []))
                if scores is not None:
                    view["score"] = round(scores.get(note.id, 0.0), 4)
                out.append(view)
            return out

    def suggest(
        self,
        tenant_id: str,
        scope: AccessScope,
        *,
        entity_ids: list[str] | None = None,
        signature: list[str] | None = None,
        text: str | None = None,
        kinds: tuple[str, ...] = ("lesson", "playbook", "decision"),
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Notes from *similar situations*, best-proven first.

        Similarity is a weighted overlap between the situation's features and
        the note's signature. Rare features (a specific technique or CVE) weigh
        more than common ones (``type:asset``), using inverse document
        frequency over all notes; a note is scored mainly on how much of the
        situation it covers, with a light penalty for specifics the situation
        lacks. The result is multiplied by how proven the note is (Wilson lower
        bound of its success rate), so a note never tried ranks below one that
        worked and above one that failed.
        """
        for kind in kinds:
            if kind not in KINDS:
                raise ValidationFailed(f"kind must be one of {', '.join(KINDS)}")
        limit = max(1, min(limit, 50))
        with self.db.transaction() as session:
            reader = GraphReader(session, tenant_id)
            resolved = [reader.resolve_id(i) for i in (entity_ids or [])[:_MAX_LINKS]]
            features = set(self.features_for(session, tenant_id, resolved)) | set(self._clean_features(signature))
            if not features and not (text and text.strip()):
                return []
            candidates: dict[str, int] = {}
            if features:
                rows = session.execute(
                    select(MemoryTerm.note_id, func.count())
                    .where(MemoryTerm.tenant_id == tenant_id, MemoryTerm.term.in_([f"f:{f}" for f in features]))
                    .group_by(MemoryTerm.note_id)
                ).all()
                candidates = {note_id: int(shared) for note_id, shared in rows}
            lexical = self._bm25(session, tenant_id, [f"w:{t}" for t in tokenize(text)]) if text else {}
            top_lexical = max(lexical.values(), default=0.0)
            ids = sorted(set(candidates) | set(lexical))
            if not ids:
                return []
            notes: list[MemoryNote] = []
            for chunk in chunked(ids):
                notes.extend(
                    session.execute(
                        select(MemoryNote).where(
                            MemoryNote.tenant_id == tenant_id,
                            MemoryNote.id.in_(chunk),
                            MemoryNote.status == "active",
                            MemoryNote.kind.in_(kinds),
                            or_(MemoryNote.expires_at.is_(None), MemoryNote.expires_at > utcnow()),
                        )
                    ).scalars()
                )
            links = self._links(session, tenant_id, [n.id for n in notes])
            visible = self._visible(session, tenant_id, scope, links, [n.id for n in notes])
            weights = self._feature_weights(
                session, tenant_id, features | {f for n in notes for f in (n.signature or [])}
            )
            situation_weight = sum(weights[f] for f in features)
            ranked = []
            for note in notes:
                if note.id not in visible:
                    continue
                own = set(note.signature or [])
                shared = sorted(features & own)
                covered = sum(weights[f] for f in shared)
                extra = sum(weights[f] for f in own - features)
                denominator = situation_weight + _EXTRA_FEATURE_PENALTY * extra
                similarity = covered / denominator if denominator > 0 else 0.0
                lexical_part = (lexical.get(note.id, 0.0) / top_lexical) if top_lexical > 0 else 0.0
                trials = note.successes + note.failures
                proven = wilson_lower_bound(note.successes, trials)
                disproven = wilson_lower_bound(note.failures, trials)
                score = (0.7 * similarity + 0.3 * lexical_part) * (0.5 + proven - 0.5 * disproven)
                if score <= 0:
                    continue
                view = self._view(note, links.get(note.id, []))
                view.update(score=round(score, 4), similarity=round(similarity, 4), shared_features=shared)
                ranked.append(view)
            ranked.sort(key=lambda v: (-v["score"], v["id"]))
            return ranked[:limit]

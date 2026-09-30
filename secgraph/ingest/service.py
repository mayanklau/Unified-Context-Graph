"""Ingestion: validate → resolve → merge → version → emit.

Guarantees
----------
* **Idempotent.** Re-sending a batch changes nothing except ``last_seen``.
* **Nothing is dropped.** A record that fails validation is quarantined with
  the reason and can be replayed after the mapping or ontology is fixed.
* **One entity, one node.** Records are resolved through the identity spine
  (``node_aliases``); when resolution would have to guess it creates a
  conflict for a human instead of merging.
* **History is kept.** Every change to a node or edge closes the previous
  version, so the graph can be read as of any past time.
* **Every change is announced.** Change events are written in the same
  transaction as the change.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import or_, select, tuple_, update
from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import LimitExceeded, ValidationFailed
from secgraph.events.outbox import ChangeBuffer
from secgraph.governance import audit
from secgraph.ingest.canonical import EdgeInput, EndpointRef, IngestRequest, NodeInput
from secgraph.observability import INGEST_BATCH_SECONDS, INGEST_RECORDS, RESOLUTION_CONFLICTS, get_logger
from secgraph.ontology.model import NodeTypeDef, Ontology
from secgraph.ontology.validate import (
    check_edge_endpoints,
    coerce_properties,
    format_datetime,
    normalize_identifiers,
    parse_datetime,
)
from secgraph.store.db import Database, ensure_tenant
from secgraph.store.models import (
    Edge,
    IngestBatch,
    Node,
    NodeAlias,
    NodeVersion,
    QuarantinedRecord,
    ResolutionConflict,
)
from secgraph.store.repository import chunked
from secgraph.store.types import utcnow

log = get_logger(__name__)

_MAX_QUARANTINE_REPORTED = 100
_FUTURE_TOLERANCE = timedelta(hours=24)
# Alias kinds with this prefix record a steward's decision about an ambiguous weak identifier.
PIN_PREFIX = "pin."
_EXPLICIT_NAME_RANK = -1
_UNNAMED_RANK = 999


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- #
# Prepared (validated, normalised) records
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class PreparedNode:
    index: int
    raw: dict[str, Any]
    type: str
    idents: list[tuple[str, str]]
    properties: dict[str, Any]
    name: str | None
    ref: str | None
    observed_at: datetime
    confidence: float | None
    op: str
    stub: bool = False


@dataclass(slots=True)
class PreparedEndpoint:
    ref: str | None = None
    id: str | None = None
    node: PreparedNode | None = None


@dataclass(slots=True)
class PreparedEdge:
    index: int
    raw: dict[str, Any]
    type: str
    source: PreparedEndpoint
    target: PreparedEndpoint
    key: str
    properties: dict[str, Any]
    observed_at: datetime
    confidence: float | None
    op: str


@dataclass(slots=True)
class Rejection:
    kind: str  # node | edge
    index: int
    record: dict[str, Any]
    reason: str


@dataclass
class Counts:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    quarantined: int = 0

    def add(self, other: Counts) -> None:
        self.created += other.created
        self.updated += other.updated
        self.unchanged += other.unchanged
        self.deleted += other.deleted
        self.quarantined += other.quarantined

    def as_dict(self) -> dict[str, int]:
        return {
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "deleted": self.deleted,
            "quarantined": self.quarantined,
        }


@dataclass
class IngestResult:
    batch_id: str
    source: str
    nodes: Counts = field(default_factory=Counts)
    edges: Counts = field(default_factory=Counts)
    stubs_created: int = 0
    conflicts: int = 0
    refs: dict[str, str] = field(default_factory=dict)
    rejections: list[Rejection] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "source": self.source,
            "nodes": self.nodes.as_dict(),
            "edges": self.edges.as_dict(),
            "stubs_created": self.stubs_created,
            "conflicts": self.conflicts,
            "refs": self.refs,
            "quarantined": [
                {"kind": r.kind, "index": r.index, "reason": r.reason}
                for r in self.rejections[:_MAX_QUARANTINE_REPORTED]
            ],
            "quarantined_total": len(self.rejections),
            "duration_ms": self.duration_ms,
        }


@dataclass
class _ChunkResult:
    nodes: Counts = field(default_factory=Counts)
    edges: Counts = field(default_factory=Counts)
    stubs_created: int = 0
    conflicts: int = 0
    refs: dict[str, tuple[str, str]] = field(default_factory=dict)
    rejections: list[Rejection] = field(default_factory=list)


class _ChunkState:
    """Everything one chunk knows about the identity spine, loaded in bulk and updated as it writes."""

    def __init__(self) -> None:
        self.alias_owner: dict[tuple[str, str, str], list[str]] = {}
        self.node_aliases: dict[str, set[tuple[str, str]]] = {}
        self.nodes: dict[str, Node] = {}
        self.conflicts: dict[str, ResolutionConflict] = {}


# --------------------------------------------------------------------------- #
class IngestService:
    def __init__(self, db: Database, ontology: Ontology, settings: Settings):
        self.db = db
        self.ontology = ontology
        self.settings = settings
        self._priority = {name: rank for rank, name in enumerate(settings.source_priority_list())}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def ingest(
        self,
        tenant_id: str,
        principal: str,
        request: IngestRequest,
        *,
        mapping: str | None = None,
        source_errors: Sequence[tuple[int, Any, str]] = (),
    ) -> IngestResult:
        """Ingest one canonical batch.

        ``source_errors`` are source records a mapping could not translate; they are
        quarantined under this batch so that they, too, are never silently lost.
        """
        total = len(request.nodes) + len(request.edges)
        if total > self.settings.ingest_max_records:
            raise LimitExceeded(
                f"batch has {total} records; the limit is {self.settings.ingest_max_records} — split the batch"
            )
        started = time.perf_counter()
        source = request.source
        batch_id = new_id()
        now = utcnow()
        default_observed = self._observed(request.observed_at, now, now)

        def _open(session: Session) -> None:
            ensure_tenant(session, tenant_id)
            session.add(
                IngestBatch(
                    id=batch_id,
                    tenant_id=tenant_id,
                    source=source,
                    mapping=mapping,
                    ontology_version=self.ontology.version,
                    ontology_fingerprint=self.ontology.fingerprint(),
                    principal=principal,
                    started_at=now,
                )
            )

        self.db.run(_open)
        result = IngestResult(batch_id=batch_id, source=source)
        refs: dict[str, tuple[str, str]] = {}

        try:
            prepared_nodes: list[PreparedNode] = []
            for index, raw in enumerate(request.nodes):
                try:
                    prepared_nodes.append(self._prepare_node(raw, index, default_observed, now))
                except ValidationFailed as exc:
                    result.rejections.append(Rejection("node", index, _as_record(raw), exc.message))
            prepared_edges: list[PreparedEdge] = []
            for index, raw in enumerate(request.edges):
                try:
                    prepared_edges.append(self._prepare_edge(raw, index, default_observed, now))
                except ValidationFailed as exc:
                    result.rejections.append(Rejection("edge", index, _as_record(raw), exc.message))
            result.nodes.quarantined = sum(1 for r in result.rejections if r.kind == "node")
            result.edges.quarantined = sum(1 for r in result.rejections if r.kind == "edge")
            for index, record, reason in source_errors:
                result.rejections.append(Rejection("source_record", index, _as_record(record), reason))
            if result.rejections:
                early = list(result.rejections)
                self.db.run(lambda s: self._quarantine(s, tenant_id, batch_id, source, early))

            size = max(1, self.settings.ingest_chunk_size)
            for chunk in chunked(prepared_nodes, size):
                outcome = self.db.run(
                    lambda s, c=chunk: self._apply_node_chunk(s, tenant_id, batch_id, source, c)  # type: ignore[misc]
                )
                self._absorb(result, refs, outcome)
            for edge_chunk in chunked(prepared_edges, size):
                outcome = self.db.run(
                    lambda s, c=edge_chunk: self._apply_edge_chunk(  # type: ignore[misc]
                        s, tenant_id, batch_id, source, c, refs
                    )
                )
                self._absorb(result, refs, outcome)
        except Exception as exc:
            self._close_batch(tenant_id, batch_id, principal, result, status="failed", error=str(exc)[:2000])
            raise

        result.refs = {ref: node_id for ref, (node_id, _type) in refs.items()}
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        self._close_batch(tenant_id, batch_id, principal, result, status="completed", error=None)
        self._metrics(result, time.perf_counter() - started)
        log.info(
            "ingest batch",
            batch_id=batch_id,
            source=source,
            nodes=result.nodes.as_dict(),
            edges=result.edges.as_dict(),
            conflicts=result.conflicts,
            duration_ms=result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------ #
    # Preparation (pure; no database)
    # ------------------------------------------------------------------ #
    def _observed(self, value: Any, default: datetime, now: datetime) -> datetime:
        if value is None:
            return default
        try:
            observed = parse_datetime(value)
        except ValueError as exc:
            raise ValidationFailed(f"observed_at: {exc}") from exc
        if observed > now + _FUTURE_TOLERANCE:
            raise ValidationFailed(f"observed_at {format_datetime(observed)} is in the future")
        return min(observed, now)

    def _prepare_node(
        self, raw: Any, index: int, default_observed: datetime, now: datetime, *, stub: bool = False
    ) -> PreparedNode:
        if not isinstance(raw, dict):
            raise ValidationFailed("record must be an object")
        try:
            record = NodeInput.model_validate(raw)
        except ValidationError as exc:
            raise ValidationFailed(_pydantic_reason(exc)) from exc
        type_def = self.ontology.node_type(record.type)
        if type_def is None:
            raise ValidationFailed(f"unknown node type '{record.type}'")
        idents = normalize_identifiers(record.type, type_def, record.identifiers)
        properties = coerce_properties(
            record.type,
            type_def.properties,
            type_def.additional_properties,
            record.properties,
            enforce_required=False,
            max_bytes=self.settings.max_property_bytes,
        )
        return PreparedNode(
            index=index,
            raw=raw,
            type=record.type,
            idents=idents,
            properties=properties,
            name=record.name.strip() if record.name and record.name.strip() else None,
            ref=record.ref,
            observed_at=self._observed(record.observed_at, default_observed, now),
            confidence=record.confidence,
            op=record.op,
            stub=stub,
        )

    def _prepare_endpoint(
        self, endpoint: EndpointRef, index: int, observed: datetime, now: datetime
    ) -> PreparedEndpoint:
        if endpoint.ref is not None:
            return PreparedEndpoint(ref=endpoint.ref)
        if endpoint.id is not None:
            return PreparedEndpoint(id=endpoint.id)
        node = self._prepare_node(
            {"type": endpoint.type, "identifiers": endpoint.identifiers}, index, observed, now, stub=True
        )
        return PreparedEndpoint(node=node)

    def _prepare_edge(self, raw: Any, index: int, default_observed: datetime, now: datetime) -> PreparedEdge:
        if not isinstance(raw, dict):
            raise ValidationFailed("record must be an object")
        try:
            record = EdgeInput.model_validate(raw)
        except ValidationError as exc:
            raise ValidationFailed(_pydantic_reason(exc)) from exc
        edge_def = self.ontology.edge_type(record.type)
        if edge_def is None:
            raise ValidationFailed(f"unknown edge type '{record.type}'")
        properties = coerce_properties(
            record.type,
            edge_def.properties,
            edge_def.additional_properties,
            record.properties,
            enforce_required=record.op == "upsert",
            max_bytes=self.settings.max_property_bytes,
        )
        observed = self._observed(record.observed_at, default_observed, now)
        return PreparedEdge(
            index=index,
            raw=raw,
            type=record.type,
            source=self._prepare_endpoint(record.source, index, observed, now),
            target=self._prepare_endpoint(record.target, index, observed, now),
            key=record.key.strip(),
            properties=properties,
            observed_at=observed,
            confidence=record.confidence,
            op=record.op,
        )

    # ------------------------------------------------------------------ #
    # Identity spine
    # ------------------------------------------------------------------ #
    def _load_state(self, session: Session, tenant_id: str, nodes: Sequence[PreparedNode]) -> _ChunkState:
        state = _ChunkState()
        values_by_type: dict[str, set[str]] = {}
        for p in nodes:
            values_by_type.setdefault(p.type, set()).update(value for _kind, value in p.idents)
        candidate_ids: set[str] = set()
        for node_type, values in values_by_type.items():
            for chunk in chunked(sorted(values)):
                rows = session.execute(
                    select(NodeAlias.kind, NodeAlias.value, NodeAlias.node_id).where(
                        NodeAlias.tenant_id == tenant_id,
                        NodeAlias.node_type == node_type,
                        NodeAlias.value.in_(chunk),
                    )
                )
                for kind, value, node_id in rows:
                    owners = state.alias_owner.setdefault((node_type, kind, value), [])
                    if node_id not in owners:
                        owners.append(node_id)
                    candidate_ids.add(node_id)
        self._load_nodes(session, tenant_id, state, candidate_ids)
        return state

    def _load_nodes(self, session: Session, tenant_id: str, state: _ChunkState, ids: set[str]) -> None:
        missing = sorted(i for i in ids if i not in state.nodes)
        for chunk in chunked(missing):
            # Rows are locked (in id order) for the rest of the transaction: two writers merging into the
            # same entity take turns, and the second one merges into what the first one committed.
            locked = (
                select(Node)
                .where(Node.tenant_id == tenant_id, Node.id.in_(chunk))
                .order_by(Node.id)
                .with_for_update(key_share=True)
                .execution_options(populate_existing=True)
            )
            for node in session.execute(locked).scalars():
                state.nodes[node.id] = node
                state.node_aliases.setdefault(node.id, set())
            rows = session.execute(
                select(NodeAlias.node_id, NodeAlias.kind, NodeAlias.value).where(
                    NodeAlias.tenant_id == tenant_id, NodeAlias.node_id.in_(chunk)
                )
            )
            for node_id, kind, value in rows:
                state.node_aliases.setdefault(node_id, set()).add((kind, value))

    def _resolve(
        self, state: _ChunkState, p: PreparedNode, type_def: NodeTypeDef
    ) -> tuple[Node | None, list[tuple[str, list[str], dict[str, Any]]]]:
        """Return the node this record describes (or ``None`` for a new entity) and any conflicts."""
        conflicts: list[tuple[str, list[str], dict[str, Any]]] = []
        strong: list[str] = []
        weak: list[str] = []
        exclusive: dict[str, str] = {}
        for kind, value in p.idents:
            definition = type_def.identifier(kind)
            assert definition is not None
            if definition.exclusive:
                exclusive[kind] = value
            if not definition.match:
                continue
            owners = [o for o in state.alias_owner.get((p.type, kind, value), []) if o in state.nodes]
            (weak if definition.weak else strong).extend(owners)
        strong = list(dict.fromkeys(strong))
        weak = list(dict.fromkeys(weak))

        def compatible(node_id: str) -> bool:
            held: dict[str, set[str]] = {}
            for kind, value in state.node_aliases.get(node_id, ()):
                if kind in exclusive:
                    held.setdefault(kind, set()).add(value)
            return all(exclusive[kind] in values for kind, values in held.items())

        identifiers = dict(p.idents)
        if strong:
            accepted = [n for n in strong if compatible(n)]
            rejected = [n for n in strong if n not in accepted]
            if rejected:
                conflicts.append(("exclusive_mismatch", rejected + accepted[:1], {"identifiers": identifiers}))
            if len(accepted) > 1:
                conflicts.append(("multiple_strong_matches", accepted, {"identifiers": identifiers}))
            return (state.nodes[accepted[0]] if accepted else None), conflicts
        if weak:
            usable = [n for n in weak if compatible(n)]
            if len(usable) == 1:
                return state.nodes[usable[0]], conflicts
            if len(usable) > 1:
                # A steward may have settled this ambiguity before ("records known only by this
                # host name mean that node"): the decision is stored as a pin and honoured here.
                pinned = [n for n in self._pinned(state, p, type_def) if compatible(n)]
                if pinned:
                    return state.nodes[pinned[0]], conflicts
                # Several entities share this weak identifier. If exactly one of them is itself
                # known only by weak identifiers, it is the placeholder created the first time
                # this ambiguity was seen — reuse it rather than minting a duplicate every run.
                placeholders = [n for n in usable if self._weak_only(state, n, type_def)]
                if len(placeholders) == 1:
                    return state.nodes[placeholders[0]], conflicts
                conflicts.append(("ambiguous_weak_match", usable, {"identifiers": identifiers}))
        return None, conflicts

    @staticmethod
    def _pinned(state: _ChunkState, p: PreparedNode, type_def: NodeTypeDef) -> list[str]:
        found: list[str] = []
        for kind, value in p.idents:
            definition = type_def.identifier(kind)
            if definition is None or not definition.weak or not definition.match:
                continue
            for owner in state.alias_owner.get((p.type, PIN_PREFIX + kind, value), []):
                if owner in state.nodes and owner not in found:
                    found.append(owner)
        return found

    @staticmethod
    def _weak_only(state: _ChunkState, node_id: str, type_def: NodeTypeDef) -> bool:
        for kind, _value in state.node_aliases.get(node_id, ()):
            definition = type_def.identifier(kind)
            if definition is not None and not definition.weak:
                return False
        return True

    def _register_aliases(
        self, session: Session, tenant_id: str, state: _ChunkState, node: Node, p: PreparedNode, type_def: NodeTypeDef
    ) -> None:
        owned = state.node_aliases.setdefault(node.id, set())
        for kind, value in p.idents:
            if (kind, value) in owned:
                continue
            definition = type_def.identifier(kind)
            assert definition is not None
            owners = state.alias_owner.setdefault((p.type, kind, value), [])
            if not definition.weak and owners:
                continue  # a strong identifier already belongs to another entity; the conflict is recorded
            if definition.exclusive and any(k == kind for k, _v in owned):
                continue  # never give an entity a second value of an exclusive identifier
            session.add(
                NodeAlias(
                    tenant_id=tenant_id,
                    node_type=p.type,
                    kind=kind,
                    value=value,
                    node_id=node.id,
                    weak=definition.weak,
                )
            )
            owners.append(node.id)
            owned.add((kind, value))

    def _record_conflicts(
        self,
        session: Session,
        tenant_id: str,
        state: _ChunkState,
        node_type: str,
        conflicts: list[tuple[str, list[str], dict[str, Any]]],
        now: datetime,
    ) -> int:
        recorded = 0
        for reason, node_ids, detail in conflicts:
            ids = sorted(set(node_ids))
            fingerprint = hashlib.sha256(f"{node_type}|{reason}|{','.join(ids)}".encode()).hexdigest()
            row = state.conflicts.get(fingerprint)
            if row is None:
                row = session.execute(
                    select(ResolutionConflict).where(
                        ResolutionConflict.tenant_id == tenant_id, ResolutionConflict.fingerprint == fingerprint
                    )
                ).scalar_one_or_none()
            if row is None:
                row = ResolutionConflict(
                    id=new_id(),
                    tenant_id=tenant_id,
                    fingerprint=fingerprint,
                    node_type=node_type,
                    reason=reason,
                    node_ids=ids,
                    detail=detail,
                    occurrences=1,
                    first_seen=now,
                    last_seen=now,
                )
                session.add(row)
                recorded += 1
            else:
                row.occurrences += 1
                row.last_seen = now
                row.detail = detail
            state.conflicts[fingerprint] = row
        return recorded

    # ------------------------------------------------------------------ #
    # Node upsert
    # ------------------------------------------------------------------ #
    def _rank(self, source: str) -> int:
        return self._priority.get(source, len(self._priority))

    def _merge_properties(
        self,
        existing: dict[str, Any],
        prop_sources: dict[str, str],
        incoming: dict[str, Any],
        source: str,
        *,
        stale: bool,
    ) -> tuple[dict[str, Any], dict[str, str], list[str]]:
        merged = dict(existing)
        owners = dict(prop_sources)
        changed: list[str] = []
        rank = self._rank(source)
        for key, value in incoming.items():
            present = key in merged
            if present:
                if stale:
                    continue  # an older observation never overwrites a newer one from the same source
                owner = owners.get(key)
                if owner and owner != source and rank > self._rank(owner):
                    continue  # a lower-priority source never overwrites a higher-priority one
            if value is None:
                if present:
                    del merged[key]
                    owners.pop(key, None)
                    changed.append(key)
                continue
            if not present or merged[key] != value:
                merged[key] = value
                changed.append(key)
            owners[key] = source
        return merged, owners, changed

    def _display_name(self, p: PreparedNode, type_def: NodeTypeDef) -> tuple[int, str | None]:
        """Best display name this record can offer, and how good it is (lower rank = better)."""
        if p.name:
            return _EXPLICIT_NAME_RANK, p.name[:512]
        by_kind: dict[str, str] = {}
        for kind, identifier in p.idents:
            by_kind.setdefault(kind, identifier)
        for rank, ref in enumerate(type_def.name_from):
            value = p.properties.get(ref)
            if value is None:
                value = by_kind.get(ref)
            if isinstance(value, str | int | float) and not isinstance(value, bool) and str(value).strip():
                return rank, str(value).strip()[:512]
        return _UNNAMED_RANK, None

    def _missing_required(self, type_def: NodeTypeDef, type_name: str, properties: dict[str, Any]) -> str | None:
        missing = [n for n, d in type_def.properties.items() if d.required and properties.get(n) is None]
        if missing:
            return "; ".join(f"{type_name}.{n}: required" for n in missing)
        return None

    def _snapshot(self, session: Session, node: Node, now: datetime) -> None:
        session.add(
            NodeVersion(
                node_id=node.id,
                version=node.version,
                tenant_id=node.tenant_id,
                type=node.type,
                name=node.name,
                properties=dict(node.properties or {}),
                stub=node.stub,
                deleted=node.deleted_at is not None,
                valid_from=node.valid_from,
                valid_to=now,
                changed_by=node.changed_by,
            )
        )

    def _upsert_node(
        self,
        session: Session,
        tenant_id: str,
        source: str,
        state: _ChunkState,
        p: PreparedNode,
        now: datetime,
        changes: ChangeBuffer,
        result: _ChunkResult,
    ) -> Node | None:
        """Apply one prepared node. Returns the node, or ``None`` when the record was rejected or a no-op delete."""
        type_def = self.ontology.node_types[p.type]
        node, conflicts = self._resolve(state, p, type_def)
        if conflicts:
            result.conflicts += self._record_conflicts(session, tenant_id, state, p.type, conflicts, now)
        observed_iso = format_datetime(p.observed_at)

        if p.op == "delete":
            if node is None or node.deleted_at is not None:
                result.nodes.unchanged += 1
                return None
            self._delete_node(session, tenant_id, source, node, now, changes)
            result.nodes.deleted += 1
            return None

        if node is None:
            properties = {k: v for k, v in p.properties.items() if v is not None}
            if not p.stub:
                problem = self._missing_required(type_def, p.type, properties)
                if problem:
                    result.rejections.append(Rejection("node", p.index, _as_record(p.raw), problem))
                    result.nodes.quarantined += 1
                    return None
            rank, name = self._display_name(p, type_def)
            name = name or p.idents[0][1]
            node = Node(
                id=new_id(),
                tenant_id=tenant_id,
                type=p.type,
                name=name,
                name_norm=name.lower(),
                name_rank=rank,
                properties=properties,
                prop_sources=dict.fromkeys(properties, source),
                sources={source: observed_iso},
                stub=p.stub,
                confidence=p.confidence if p.confidence is not None else 1.0,
                first_seen=p.observed_at,
                last_seen=p.observed_at,
                version=1,
                valid_from=now,
                created_at=now,
                updated_at=now,
                changed_by=source,
            )
            session.add(node)
            state.nodes[node.id] = node
            self._register_aliases(session, tenant_id, state, node, p, type_def)
            changes.add("node.created", p.type, node.id, {"name": name, "source": source, "stub": p.stub})
            if p.stub:
                result.stubs_created += 1
            else:
                result.nodes.created += 1
            return node

        # ---- existing entity ------------------------------------------------
        previous_seen = (node.sources or {}).get(source)
        stale = previous_seen is not None and observed_iso < previous_seen
        resurrect = node.deleted_at is not None
        if p.stub and not resurrect:
            merged, owners = dict(node.properties or {}), dict(node.prop_sources or {})
            changed_keys: list[str] = []
        else:
            merged, owners, changed_keys = self._merge_properties(
                dict(node.properties or {}), dict(node.prop_sources or {}), p.properties, source, stale=stale
            )
        becomes_full = node.stub and not p.stub
        if not p.stub and (becomes_full or changed_keys):
            problem = self._missing_required(type_def, p.type, merged)
            if problem:
                result.rejections.append(Rejection("node", p.index, _as_record(p.raw), problem))
                result.nodes.quarantined += 1
                return node
        rank, name = self._display_name(p, type_def)
        rename = name is not None and rank <= node.name_rank and name != node.name and not (stale and not p.name)
        changed = bool(changed_keys) or becomes_full or resurrect or rename

        if changed:
            self._snapshot(session, node, now)
            node.version += 1
            node.valid_from = now
            node.updated_at = now
            node.changed_by = source
            node.properties = merged
            node.prop_sources = owners
            if becomes_full:
                node.stub = False
            if resurrect:
                node.deleted_at = None
            if rename and name is not None:
                node.name = name
                node.name_norm = name.lower()
                node.name_rank = rank
            changes.add(
                "node.updated",
                p.type,
                node.id,
                {"name": node.name, "source": source, "changed": sorted(changed_keys), "restored": resurrect},
            )
        elif name is not None and rank < node.name_rank:
            node.name_rank = rank

        if p.observed_at > node.last_seen:
            node.last_seen = p.observed_at
        if p.observed_at < node.first_seen:
            node.first_seen = p.observed_at
        if previous_seen is None or observed_iso > previous_seen:
            node.sources = {**(node.sources or {}), source: observed_iso}
        if p.confidence is not None and not p.stub and p.confidence != node.confidence:
            node.confidence = p.confidence
        self._register_aliases(session, tenant_id, state, node, p, type_def)
        if not p.stub:
            if changed:
                result.nodes.updated += 1
            else:
                result.nodes.unchanged += 1
        return node

    def _delete_node(
        self, session: Session, tenant_id: str, source: str, node: Node, now: datetime, changes: ChangeBuffer
    ) -> None:
        self._snapshot(session, node, now)
        node.version += 1
        node.valid_from = now
        node.updated_at = now
        node.deleted_at = now
        node.changed_by = source
        session.flush()
        closed = session.execute(
            update(Edge)
            .where(
                Edge.tenant_id == tenant_id,
                Edge.valid_to.is_(None),
                or_(Edge.src_id == node.id, Edge.dst_id == node.id),
            )
            .values(valid_to=now)
            .execution_options(synchronize_session=False)
        )
        closed_count = int(getattr(closed, "rowcount", 0) or 0)
        changes.add(
            "node.deleted", node.type, node.id, {"name": node.name, "source": source, "edges_closed": closed_count}
        )

    def _apply_node_chunk(
        self, session: Session, tenant_id: str, batch_id: str, source: str, chunk: Sequence[PreparedNode]
    ) -> _ChunkResult:
        result = _ChunkResult()
        changes = ChangeBuffer()
        now = utcnow()
        state = self._load_state(session, tenant_id, chunk)
        for p in chunk:
            node = self._upsert_node(session, tenant_id, source, state, p, now, changes, result)
            if p.ref and node is not None:
                result.refs[p.ref] = (node.id, node.type)
        if result.rejections:
            self._quarantine(session, tenant_id, batch_id, source, result.rejections)
        changes.flush(session, tenant_id, batch_id)
        return result

    # ------------------------------------------------------------------ #
    # Edge upsert
    # ------------------------------------------------------------------ #
    def _apply_edge_chunk(
        self,
        session: Session,
        tenant_id: str,
        batch_id: str,
        source: str,
        chunk: Sequence[PreparedEdge],
        refs: dict[str, tuple[str, str]],
    ) -> _ChunkResult:
        result = _ChunkResult()
        changes = ChangeBuffer()
        now = utcnow()

        # 1. Endpoints given by identifiers go through the same identity spine as nodes.
        endpoint_nodes: list[PreparedNode] = []
        for e in chunk:
            for endpoint in (e.source, e.target):
                if endpoint.node is not None:
                    endpoint_nodes.append(endpoint.node)
        state = self._load_state(session, tenant_id, endpoint_nodes)
        by_id_wanted = {ep.id for e in chunk for ep in (e.source, e.target) if ep.id is not None}
        self._load_nodes(session, tenant_id, state, by_id_wanted)

        def resolve_endpoint(endpoint: PreparedEndpoint, create: bool) -> tuple[str, str] | str:
            if endpoint.ref is not None:
                found = refs.get(endpoint.ref)
                return (
                    found if found else f"unknown ref '{endpoint.ref}' (the node was rejected or is not in this batch)"
                )
            if endpoint.id is not None:
                existing = state.nodes.get(endpoint.id)
                if existing is None or existing.deleted_at is not None:
                    return f"node id '{endpoint.id}' does not exist"
                return existing.id, existing.type
            assert endpoint.node is not None
            p = endpoint.node
            if not create:
                node, _conflicts = self._resolve(state, p, self.ontology.node_types[p.type])
                if node is None or node.deleted_at is not None:
                    return "endpoint does not exist"
                return node.id, node.type
            node = self._upsert_node(session, tenant_id, source, state, p, now, changes, result)
            if node is None:
                return "endpoint could not be resolved"
            return node.id, node.type

        resolved: list[tuple[PreparedEdge, str, str]] = []
        for e in chunk:
            edge_def = self.ontology.edge_types[e.type]
            create = e.op == "upsert"
            src = resolve_endpoint(e.source, create)
            dst = resolve_endpoint(e.target, create) if not isinstance(src, str) else src
            problem: str | None = None
            if isinstance(src, str):
                problem = f"source: {src}"
            elif isinstance(dst, str):
                problem = f"target: {dst}"
            else:
                try:
                    check_edge_endpoints(e.type, edge_def, src[1], dst[1])
                except ValidationFailed as exc:
                    problem = exc.message
                if problem is None and src[0] == dst[0]:
                    problem = f"{e.type}: source and target are the same entity"
            if problem is not None:
                if e.op == "delete" and "does not exist" in problem:
                    result.edges.unchanged += 1
                    continue
                result.rejections.append(Rejection("edge", e.index, _as_record(e.raw), problem))
                result.edges.quarantined += 1
                continue
            assert not isinstance(src, str) and not isinstance(dst, str)
            resolved.append((e, src[0], dst[0]))

        # 2. Load the current version of every edge in the chunk in bulk.
        session.flush()
        keys = sorted({(e.type, s, d, e.key) for e, s, d in resolved})
        current: dict[tuple[str, str, str, str], Edge] = {}
        for key_chunk in chunked(keys, 200):
            rows = session.execute(
                select(Edge)
                .where(
                    Edge.tenant_id == tenant_id,
                    Edge.valid_to.is_(None),
                    tuple_(Edge.type, Edge.src_id, Edge.dst_id, Edge.edge_key).in_(key_chunk),
                )
                .order_by(Edge.id)
                .with_for_update(key_share=True)
            ).scalars()
            for existing in rows:
                current[(existing.type, existing.src_id, existing.dst_id, existing.edge_key)] = existing

        # 3. Apply. New rows are inserted only after every close has been flushed, so the
        #    "one current version per relationship" index can never see two current rows.
        new_rows: list[Edge] = []
        for e, src_id, dst_id in resolved:
            key = (e.type, src_id, dst_id, e.key)
            row = current.get(key)
            observed_iso = format_datetime(e.observed_at)
            if e.op == "delete":
                if row is None:
                    result.edges.unchanged += 1
                    continue
                row.valid_to = now
                current.pop(key, None)
                changes.add(
                    "edge.deleted",
                    e.type,
                    row.lineage_id,
                    {"source": src_id, "target": dst_id, "key": e.key, "by": source},
                )
                result.edges.deleted += 1
                continue
            if row is None:
                properties = {k: v for k, v in e.properties.items() if v is not None}
                row = Edge(
                    id=new_id(),
                    tenant_id=tenant_id,
                    type=e.type,
                    src_id=src_id,
                    dst_id=dst_id,
                    edge_key=e.key,
                    lineage_id=new_id(),
                    properties=properties,
                    sources={source: observed_iso},
                    confidence=e.confidence if e.confidence is not None else 1.0,
                    first_seen=e.observed_at,
                    last_seen=e.observed_at,
                    version=1,
                    valid_from=now,
                )
                new_rows.append(row)
                current[key] = row
                changes.add(
                    "edge.created",
                    e.type,
                    row.lineage_id,
                    {"source": src_id, "target": dst_id, "key": e.key, "by": source},
                )
                result.edges.created += 1
                continue

            previous_seen = (row.sources or {}).get(source)
            stale = previous_seen is not None and observed_iso < previous_seen
            merged = dict(row.properties or {})
            changed_keys: list[str] = []
            if not stale:
                for name, value in e.properties.items():
                    if value is None:
                        if name in merged:
                            del merged[name]
                            changed_keys.append(name)
                    elif merged.get(name) != value:
                        merged[name] = value
                        changed_keys.append(name)
            sources = dict(row.sources or {})
            if previous_seen is None or observed_iso > previous_seen:
                sources[source] = observed_iso
            confidence = e.confidence if e.confidence is not None else row.confidence
            if changed_keys:
                # Close the current version and open its successor.
                row.valid_to = now
                successor = Edge(
                    id=new_id(),
                    tenant_id=tenant_id,
                    type=e.type,
                    src_id=src_id,
                    dst_id=dst_id,
                    edge_key=e.key,
                    lineage_id=row.lineage_id,
                    properties=merged,
                    sources=sources,
                    confidence=confidence,
                    first_seen=min(row.first_seen, e.observed_at),
                    last_seen=max(row.last_seen, e.observed_at),
                    version=row.version + 1,
                    valid_from=now,
                )
                new_rows.append(successor)
                current[key] = successor
                changes.add(
                    "edge.updated",
                    e.type,
                    row.lineage_id,
                    {"source": src_id, "target": dst_id, "key": e.key, "by": source, "changed": sorted(changed_keys)},
                )
                result.edges.updated += 1
            else:
                if e.observed_at > row.last_seen:
                    row.last_seen = e.observed_at
                if e.observed_at < row.first_seen:
                    row.first_seen = e.observed_at
                if sources != (row.sources or {}):
                    row.sources = sources
                if confidence != row.confidence:
                    row.confidence = confidence
                result.edges.unchanged += 1

        session.flush()
        session.add_all(new_rows)
        if result.rejections:
            self._quarantine(session, tenant_id, batch_id, source, result.rejections)
        changes.flush(session, tenant_id, batch_id)
        return result

    # ------------------------------------------------------------------ #
    # Bookkeeping
    # ------------------------------------------------------------------ #
    def _quarantine(
        self, session: Session, tenant_id: str, batch_id: str, source: str, rejections: Sequence[Rejection]
    ) -> None:
        now = utcnow()
        session.add_all(
            [
                QuarantinedRecord(
                    id=new_id(),
                    tenant_id=tenant_id,
                    batch_id=batch_id,
                    source=source,
                    kind=r.kind,
                    record=r.record,
                    reason=r.reason[:4000],
                    created_at=now,
                )
                for r in rejections
            ]
        )

    def _absorb(self, result: IngestResult, refs: dict[str, tuple[str, str]], outcome: _ChunkResult) -> None:
        result.nodes.add(outcome.nodes)
        result.edges.add(outcome.edges)
        result.stubs_created += outcome.stubs_created
        result.conflicts += outcome.conflicts
        result.rejections.extend(outcome.rejections)
        refs.update(outcome.refs)

    def _close_batch(
        self, tenant_id: str, batch_id: str, principal: str, result: IngestResult, *, status: str, error: str | None
    ) -> None:
        def _work(session: Session) -> None:
            batch = session.get(IngestBatch, batch_id)
            if batch is None:  # pragma: no cover - the batch row is written before any work starts
                return
            batch.status = status
            batch.finished_at = utcnow()
            batch.error = error
            batch.counts = {
                "nodes": result.nodes.as_dict(),
                "edges": result.edges.as_dict(),
                "stubs_created": result.stubs_created,
                "conflicts": result.conflicts,
                "quarantined": len(result.rejections),
            }
            audit.record(
                session,
                tenant_id,
                actor=principal,
                action=f"ingest.{status}",
                target=f"batch:{batch_id}",
                detail={"source": result.source, **batch.counts, **({"error": error} if error else {})},
            )

        try:
            self.db.run(_work)
        except Exception:  # pragma: no cover - bookkeeping must never mask the original error
            log.error("could not close ingest batch", batch_id=batch_id, exc_info=True)
            if status == "completed":
                raise

    def _metrics(self, result: IngestResult, seconds: float) -> None:
        INGEST_BATCH_SECONDS.observe(seconds)
        for kind, counts in (("node", result.nodes), ("edge", result.edges)):
            for outcome, value in counts.as_dict().items():
                if value:
                    INGEST_RECORDS.labels(kind=kind, outcome=outcome).inc(value)
        if result.conflicts:
            RESOLUTION_CONFLICTS.inc(result.conflicts)


def _pydantic_reason(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(p) for p in error["loc"]) or "record"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


def _as_record(raw: Any) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {"value": repr(raw)[:2000]}

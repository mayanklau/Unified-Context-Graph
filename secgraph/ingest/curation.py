"""Graph curation: merging entities, replaying quarantined records, expiry and retention.

These are the operations a data steward (or the maintenance worker) performs
on the graph outside normal ingestion. Each is transactional, audited and
announced on the change feed.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import partial
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import Conflict, NotFound, ValidationFailed
from secgraph.events.outbox import ChangeBuffer, prune_changes
from secgraph.governance import audit
from secgraph.ingest.canonical import IngestRequest
from secgraph.ingest.service import PIN_PREFIX, IngestService, new_id
from secgraph.observability import get_logger
from secgraph.ontology.model import Ontology
from secgraph.store.db import Database
from secgraph.store.models import (
    Edge,
    MemoryLink,
    Node,
    NodeAlias,
    NodeVersion,
    QuarantinedRecord,
    ResolutionConflict,
    Tenant,
)
from secgraph.store.types import utcnow

log = get_logger(__name__)


class CurationService:
    def __init__(self, db: Database, ontology: Ontology, settings: Settings, ingest: IngestService):
        self.db = db
        self.ontology = ontology
        self.settings = settings
        self.ingest = ingest

    # ------------------------------------------------------------------ #
    # Merge
    # ------------------------------------------------------------------ #
    def merge_nodes(self, tenant_id: str, principal: str, survivor_id: str, duplicate_id: str) -> dict[str, Any]:
        """Fold ``duplicate_id`` into ``survivor_id``. The duplicate's id keeps resolving to the survivor."""
        if survivor_id == duplicate_id:
            raise ValidationFailed("cannot merge a node into itself")

        def _work(session: Session) -> dict[str, Any]:
            now = utcnow()
            rows = {
                n.id: n
                for n in session.execute(
                    select(Node)
                    .where(Node.tenant_id == tenant_id, Node.id.in_([survivor_id, duplicate_id]))
                    .order_by(Node.id)
                    .with_for_update()
                ).scalars()
            }
            survivor, duplicate = rows.get(survivor_id), rows.get(duplicate_id)
            if survivor is None or survivor.deleted_at is not None:
                raise NotFound(f"node {survivor_id} does not exist")
            if duplicate is None or duplicate.deleted_at is not None:
                raise NotFound(f"node {duplicate_id} does not exist")
            if survivor.type != duplicate.type:
                raise Conflict(f"cannot merge a {duplicate.type} into a {survivor.type}")
            changes = ChangeBuffer()

            # -- identity spine: the survivor takes every identifier of the duplicate
            def alias_pairs(node_id: str) -> set[tuple[str, str]]:
                rows_ = session.execute(
                    select(NodeAlias.kind, NodeAlias.value).where(
                        NodeAlias.tenant_id == tenant_id, NodeAlias.node_id == node_id
                    )
                )
                return {(kind, value) for kind, value in rows_}

            type_def = self.ontology.node_types[survivor.type]
            duplicate_aliases = alias_pairs(duplicate_id)
            # A duplicate known only by weak identifiers is the placeholder of an ambiguity. Merging it is
            # the steward's answer to "which entity does this name mean", so the answer is pinned.
            weak_only = all(
                (d := type_def.identifier(kind)) is None or d.weak
                for kind, _value in duplicate_aliases
                if not kind.startswith(PIN_PREFIX)
            )
            pins = (
                [
                    (kind, value)
                    for kind, value in duplicate_aliases
                    if (d := type_def.identifier(kind)) is not None and d.weak and d.match
                ]
                if weak_only
                else []
            )
            shared = alias_pairs(survivor_id) & duplicate_aliases
            for kind, value in shared:  # only weak identifiers can be held by both
                session.execute(
                    delete(NodeAlias).where(
                        NodeAlias.tenant_id == tenant_id,
                        NodeAlias.node_id == duplicate_id,
                        NodeAlias.kind == kind,
                        NodeAlias.value == value,
                    )
                )
            moved = session.execute(
                update(NodeAlias)
                .where(NodeAlias.tenant_id == tenant_id, NodeAlias.node_id == duplicate_id)
                .values(node_id=survivor_id)
            )
            moved_aliases = int(getattr(moved, "rowcount", 0) or 0)
            for kind, value in pins:
                self._pin(session, tenant_id, survivor.type, kind, value, survivor_id)

            # -- relationships: close the duplicate's edges, re-open them on the survivor
            def current_edges(node_id: str) -> list[Edge]:
                found: dict[str, Edge] = {}
                for side in (Edge.src_id, Edge.dst_id):  # one statement per endpoint index
                    for e in session.execute(
                        select(Edge).where(Edge.tenant_id == tenant_id, Edge.valid_to.is_(None), side == node_id)
                    ).scalars():
                        found[e.id] = e
                return list(found.values())

            existing = {(e.type, e.src_id, e.dst_id, e.edge_key): e for e in current_edges(survivor_id)}
            moved_edges = 0
            new_rows: list[Edge] = []
            for edge in current_edges(duplicate_id):
                edge.valid_to = now
                src = survivor_id if edge.src_id == duplicate_id else edge.src_id
                dst = survivor_id if edge.dst_id == duplicate_id else edge.dst_id
                if src == dst:
                    continue  # the edge joined the two nodes being merged
                key = (edge.type, src, dst, edge.edge_key)
                twin = existing.get(key)
                if twin is not None:
                    twin.first_seen = min(twin.first_seen, edge.first_seen)
                    twin.last_seen = max(twin.last_seen, edge.last_seen)
                    twin.sources = {**(edge.sources or {}), **(twin.sources or {})}
                    continue
                replacement = Edge(
                    id=new_id(),
                    tenant_id=tenant_id,
                    type=edge.type,
                    src_id=src,
                    dst_id=dst,
                    edge_key=edge.edge_key,
                    lineage_id=new_id(),
                    properties=dict(edge.properties or {}),
                    sources=dict(edge.sources or {}),
                    confidence=edge.confidence,
                    first_seen=edge.first_seen,
                    last_seen=edge.last_seen,
                    version=1,
                    valid_from=now,
                )
                new_rows.append(replacement)
                existing[key] = replacement
                moved_edges += 1
            session.flush()
            session.add_all(new_rows)

            # -- properties: the survivor's values win; gaps are filled from the duplicate
            merged = dict(duplicate.properties or {})
            merged.update(survivor.properties or {})
            owners = dict(duplicate.prop_sources or {})
            owners.update(survivor.prop_sources or {})
            for node in (survivor, duplicate):
                session.add(
                    NodeVersion(
                        node_id=node.id,
                        version=node.version,
                        tenant_id=tenant_id,
                        type=node.type,
                        name=node.name,
                        properties=dict(node.properties or {}),
                        stub=node.stub,
                        deleted=False,
                        valid_from=node.valid_from,
                        valid_to=now,
                        changed_by=node.changed_by,
                    )
                )
                node.version += 1
                node.valid_from = now
                node.updated_at = now
                node.changed_by = principal
            survivor.properties = merged
            survivor.prop_sources = owners
            survivor.stub = survivor.stub and duplicate.stub
            survivor.first_seen = min(survivor.first_seen, duplicate.first_seen)
            survivor.last_seen = max(survivor.last_seen, duplicate.last_seen)
            survivor.sources = {**(duplicate.sources or {}), **(survivor.sources or {})}
            duplicate.deleted_at = now
            duplicate.merged_into = survivor_id

            # -- memory and open conflicts follow the survivor
            linked = select(MemoryLink.note_id).where(
                MemoryLink.tenant_id == tenant_id, MemoryLink.node_id == survivor_id
            )
            session.execute(
                delete(MemoryLink).where(
                    MemoryLink.tenant_id == tenant_id,
                    MemoryLink.node_id == duplicate_id,
                    MemoryLink.note_id.in_(list(session.execute(linked).scalars())),
                )
            )
            session.execute(
                update(MemoryLink)
                .where(MemoryLink.tenant_id == tenant_id, MemoryLink.node_id == duplicate_id)
                .values(node_id=survivor_id)
            )
            pinned = set(pins)
            for conflict in session.execute(
                select(ResolutionConflict).where(
                    ResolutionConflict.tenant_id == tenant_id,
                    ResolutionConflict.status == "open",
                    ResolutionConflict.node_type == survivor.type,
                )
            ).scalars():
                ids = set(conflict.node_ids or [])
                identifiers = (conflict.detail or {}).get("identifiers", {})
                settled_by_pin = conflict.reason == "ambiguous_weak_match" and any(
                    (kind, value) in pinned for kind, value in identifiers.items()
                )
                if settled_by_pin or (duplicate_id in ids and (survivor_id in ids or len(ids) <= 2)):
                    conflict.status = "resolved"

            changes.add(
                "node.merged",
                survivor.type,
                duplicate_id,
                {"into": survivor_id, "aliases_moved": moved_aliases, "edges_moved": moved_edges, "by": principal},
            )
            changes.add(
                "node.updated", survivor.type, survivor_id, {"name": survivor.name, "merged_from": duplicate_id}
            )
            changes.flush(session, tenant_id)
            summary = {
                "survivor": survivor_id,
                "merged": duplicate_id,
                "aliases_moved": moved_aliases,
                "edges_moved": moved_edges,
            }
            audit.record(
                session, tenant_id, actor=principal, action="node.merge", target=f"node:{survivor_id}", detail=summary
            )
            return summary

        return self.db.run(_work)

    @staticmethod
    def _pin(session: Session, tenant_id: str, node_type: str, kind: str, value: str, node_id: str) -> None:
        """Record that weak identifier ``kind=value`` means ``node_id`` (replacing any earlier decision)."""
        session.execute(
            delete(NodeAlias).where(
                NodeAlias.tenant_id == tenant_id,
                NodeAlias.node_type == node_type,
                NodeAlias.kind == PIN_PREFIX + kind,
                NodeAlias.value == value,
            )
        )
        session.add(
            NodeAlias(
                tenant_id=tenant_id,
                node_type=node_type,
                kind=PIN_PREFIX + kind,
                value=value,
                node_id=node_id,
                weak=False,
            )
        )
        session.flush()

    def resolve_conflict(self, tenant_id: str, principal: str, conflict_id: str, node_id: str) -> dict[str, Any]:
        """Settle a conflict by naming the node the records belong to.

        * ``ambiguous_weak_match`` — the weak identifier is pinned to ``node_id`` and any placeholder
          created for it is merged in; future records resolve without asking again.
        * ``multiple_strong_matches`` / ``exclusive_mismatch`` — the steward asserts the listed nodes are
          one entity: the others are merged into ``node_id``.
        """
        with self.db.transaction() as session:
            conflict = session.execute(
                select(ResolutionConflict).where(
                    ResolutionConflict.tenant_id == tenant_id, ResolutionConflict.id == conflict_id
                )
            ).scalar_one_or_none()
            if conflict is None:
                raise NotFound(f"conflict {conflict_id} does not exist")
            if conflict.status != "open":
                raise Conflict(f"conflict {conflict_id} is already {conflict.status}")
            node = session.execute(
                select(Node).where(Node.tenant_id == tenant_id, Node.id == node_id, Node.deleted_at.is_(None))
            ).scalar_one_or_none()
            if node is None or node.type != conflict.node_type:
                raise NotFound(f"node {node_id} is not a current {conflict.node_type}")
            reason = conflict.reason
            candidates = [i for i in (conflict.node_ids or []) if i != node_id]
            identifiers = dict((conflict.detail or {}).get("identifiers", {}))
            node_type = conflict.node_type
            type_def = self.ontology.node_types[node_type]
            placeholders: list[str] = []
            if reason == "ambiguous_weak_match":
                weak = [
                    (kind, value)
                    for kind, value in identifiers.items()
                    if (d := type_def.identifier(kind)) is not None and d.weak and d.match
                ]
                for kind, value in weak:
                    owners = session.execute(
                        select(NodeAlias.node_id).where(
                            NodeAlias.tenant_id == tenant_id,
                            NodeAlias.node_type == node_type,
                            NodeAlias.kind == kind,
                            NodeAlias.value == value,
                        )
                    ).scalars()
                    for owner in owners:
                        if owner == node_id or owner in placeholders:
                            continue
                        kinds = session.execute(
                            select(NodeAlias.kind).where(NodeAlias.tenant_id == tenant_id, NodeAlias.node_id == owner)
                        ).scalars()
                        if all((d := type_def.identifier(k)) is None or d.weak for k in kinds):
                            placeholders.append(owner)

        merged: list[str] = []
        if reason == "ambiguous_weak_match":
            for placeholder in placeholders:
                self.merge_nodes(tenant_id, principal, node_id, placeholder)
                merged.append(placeholder)
        else:
            for other in candidates:
                try:
                    self.merge_nodes(tenant_id, principal, node_id, other)
                    merged.append(other)
                except NotFound:
                    continue  # already merged or deleted since the conflict was recorded

        def _finish(session: Session) -> None:
            if reason == "ambiguous_weak_match":
                for kind, value in identifiers.items():
                    definition = type_def.identifier(kind)
                    if definition is not None and definition.weak and definition.match:
                        self._pin(session, tenant_id, node_type, kind, value, node_id)
            row = session.execute(
                select(ResolutionConflict).where(
                    ResolutionConflict.tenant_id == tenant_id, ResolutionConflict.id == conflict_id
                )
            ).scalar_one()
            row.status = "resolved"
            audit.record(
                session,
                tenant_id,
                actor=principal,
                action="conflict.resolve",
                target=f"conflict:{conflict_id}",
                detail={"node_id": node_id, "merged": merged, "reason": reason},
            )

        self.db.run(_finish)
        return {"status": "resolved", "node_id": node_id, "merged": merged}

    # ------------------------------------------------------------------ #
    # Conflicts and quarantine
    # ------------------------------------------------------------------ #
    def list_conflicts(
        self, tenant_id: str, *, status: str = "open", limit: int = 100, offset: int = 0
    ) -> tuple[list[ResolutionConflict], int]:
        with self.db.transaction() as session:
            where = [ResolutionConflict.tenant_id == tenant_id]
            if status != "all":
                where.append(ResolutionConflict.status == status)
            total = session.execute(select(func.count()).select_from(ResolutionConflict).where(*where)).scalar_one()
            rows = list(
                session.execute(
                    select(ResolutionConflict)
                    .where(*where)
                    .order_by(ResolutionConflict.last_seen.desc())
                    .limit(limit)
                    .offset(offset)
                ).scalars()
            )
            return rows, int(total)

    def dismiss_conflict(self, tenant_id: str, principal: str, conflict_id: str) -> None:
        def _work(session: Session) -> None:
            conflict = session.execute(
                select(ResolutionConflict).where(
                    ResolutionConflict.tenant_id == tenant_id, ResolutionConflict.id == conflict_id
                )
            ).scalar_one_or_none()
            if conflict is None:
                raise NotFound(f"conflict {conflict_id} does not exist")
            conflict.status = "dismissed"
            audit.record(
                session, tenant_id, actor=principal, action="conflict.dismiss", target=f"conflict:{conflict_id}"
            )

        self.db.run(_work)

    def list_quarantine(
        self, tenant_id: str, *, status: str = "open", batch_id: str | None = None, limit: int = 100, offset: int = 0
    ) -> tuple[list[QuarantinedRecord], int]:
        with self.db.transaction() as session:
            where = [QuarantinedRecord.tenant_id == tenant_id]
            if status != "all":
                where.append(QuarantinedRecord.status == status)
            if batch_id:
                where.append(QuarantinedRecord.batch_id == batch_id)
            total = session.execute(select(func.count()).select_from(QuarantinedRecord).where(*where)).scalar_one()
            rows = list(
                session.execute(
                    select(QuarantinedRecord)
                    .where(*where)
                    .order_by(QuarantinedRecord.created_at.desc(), QuarantinedRecord.id)
                    .limit(limit)
                    .offset(offset)
                ).scalars()
            )
            return rows, int(total)

    def replay_quarantine(self, tenant_id: str, principal: str, record_ids: list[str]) -> dict[str, Any]:
        """Re-ingest quarantined records (after the mapping, the ontology or the source data was fixed).

        Records that still fail are quarantined again under the new batch; the
        originals are marked ``replayed`` either way so nothing is counted twice.
        """
        if not record_ids:
            raise ValidationFailed("no records selected")
        if len(record_ids) > 5000:
            raise ValidationFailed("replay at most 5000 records at a time")
        with self.db.transaction() as session:
            rows = list(
                session.execute(
                    select(QuarantinedRecord).where(
                        QuarantinedRecord.tenant_id == tenant_id,
                        QuarantinedRecord.id.in_(record_ids),
                        QuarantinedRecord.status == "open",
                    )
                ).scalars()
            )
            by_source: dict[str, dict[str, list[Any]]] = {}
            for row in rows:
                bucket = by_source.setdefault(row.source or "replay", {"nodes": [], "edges": []})
                if row.kind == "edge":
                    bucket["edges"].append(row.record)
                elif row.kind == "node":
                    bucket["nodes"].append(row.record)
            replayable = [r.id for r in rows if r.kind in ("node", "edge")]
        if not replayable:
            raise NotFound("none of the selected records is open and replayable")

        results = []
        for source, bucket in by_source.items():
            if not bucket["nodes"] and not bucket["edges"]:
                continue
            outcome = self.ingest.ingest(
                tenant_id, principal, IngestRequest(source=source, nodes=bucket["nodes"], edges=bucket["edges"])
            )
            results.append(outcome.to_dict())

        def _mark(session: Session) -> None:
            now = utcnow()
            for chunk_start in range(0, len(replayable), 500):
                session.execute(
                    update(QuarantinedRecord)
                    .where(
                        QuarantinedRecord.tenant_id == tenant_id,
                        QuarantinedRecord.id.in_(replayable[chunk_start : chunk_start + 500]),
                    )
                    .values(status="replayed", resolved_at=now)
                )
            audit.record(
                session,
                tenant_id,
                actor=principal,
                action="quarantine.replay",
                detail={"records": len(replayable), "batches": [r["batch_id"] for r in results]},
            )

        self.db.run(_mark)
        return {"replayed": len(replayable), "batches": results}

    def discard_quarantine(self, tenant_id: str, principal: str, record_ids: list[str]) -> int:
        def _work(session: Session) -> int:
            result = session.execute(
                update(QuarantinedRecord)
                .where(
                    QuarantinedRecord.tenant_id == tenant_id,
                    QuarantinedRecord.id.in_(record_ids[:5000]),
                    QuarantinedRecord.status == "open",
                )
                .values(status="discarded", resolved_at=utcnow())
            )
            count = int(getattr(result, "rowcount", 0) or 0)
            audit.record(session, tenant_id, actor=principal, action="quarantine.discard", detail={"records": count})
            return count

        return self.db.run(_work)

    # ------------------------------------------------------------------ #
    # Expiry and retention (run by the maintenance worker)
    # ------------------------------------------------------------------ #
    def expire_stale(self, tenant_id: str, *, now: datetime | None = None, batch: int = 1000) -> dict[str, int]:
        """Close edges and tombstone nodes whose type declares ``ttl_days`` and that were not re-observed."""
        now = now or utcnow()
        expired = {"nodes": 0, "edges": 0}
        for edge_type, definition in self.ontology.edge_types.items():
            if not definition.ttl_days:
                continue
            cutoff = now - timedelta(days=definition.ttl_days)
            while True:
                count = self.db.run(
                    partial(self._expire_edges, tenant_id=tenant_id, edge_type=edge_type, cutoff=cutoff, batch=batch)
                )
                expired["edges"] += count
                if count < batch:
                    break
        for node_type, node_def in self.ontology.node_types.items():
            if not node_def.ttl_days:
                continue
            cutoff = now - timedelta(days=node_def.ttl_days)
            while True:
                count = self.db.run(
                    partial(self._expire_nodes, tenant_id=tenant_id, node_type=node_type, cutoff=cutoff, batch=batch)
                )
                expired["nodes"] += count
                if count < batch:
                    break
        if expired["nodes"] or expired["edges"]:
            log.info("expired stale graph elements", tenant=tenant_id, nodes=expired["nodes"], edges=expired["edges"])
        return expired

    def _expire_edges(self, session: Session, tenant_id: str, edge_type: str, cutoff: datetime, batch: int) -> int:
        now = utcnow()
        rows = list(
            session.execute(
                select(Edge)
                .where(
                    Edge.tenant_id == tenant_id,
                    Edge.type == edge_type,
                    Edge.valid_to.is_(None),
                    Edge.last_seen < cutoff,
                )
                .limit(batch)
            ).scalars()
        )
        changes = ChangeBuffer()
        for row in rows:
            row.valid_to = now
            changes.add(
                "edge.deleted",
                row.type,
                row.lineage_id,
                {"source": row.src_id, "target": row.dst_id, "key": row.edge_key, "by": "expiry"},
            )
        changes.flush(session, tenant_id)
        return len(rows)

    def _expire_nodes(self, session: Session, tenant_id: str, node_type: str, cutoff: datetime, batch: int) -> int:
        now = utcnow()
        rows = list(
            session.execute(
                select(Node)
                .where(
                    Node.tenant_id == tenant_id,
                    Node.type == node_type,
                    Node.deleted_at.is_(None),
                    Node.last_seen < cutoff,
                )
                .limit(batch)
            ).scalars()
        )
        changes = ChangeBuffer()
        for node in rows:
            self.ingest._delete_node(session, tenant_id, "expiry", node, now, changes)
        changes.flush(session, tenant_id)
        return len(rows)

    def prune_history(self, tenant_id: str, *, now: datetime | None = None) -> dict[str, int]:
        """Apply retention to the change feed and, when configured, to version history."""
        now = now or utcnow()
        pruned = {"change_events": 0, "node_versions": 0, "edge_versions": 0}

        def _work(session: Session) -> None:
            if self.settings.change_retention_days > 0:
                pruned["change_events"] = prune_changes(
                    session, tenant_id, now - timedelta(days=self.settings.change_retention_days)
                )
            if self.settings.history_retention_days > 0:
                cutoff = now - timedelta(days=self.settings.history_retention_days)
                result = session.execute(
                    delete(NodeVersion).where(NodeVersion.tenant_id == tenant_id, NodeVersion.valid_to < cutoff)
                )
                pruned["node_versions"] = int(getattr(result, "rowcount", 0) or 0)
                result = session.execute(delete(Edge).where(Edge.tenant_id == tenant_id, Edge.valid_to < cutoff))
                pruned["edge_versions"] = int(getattr(result, "rowcount", 0) or 0)

        self.db.run(_work)
        return pruned

    def tenants(self) -> list[str]:
        with self.db.transaction() as session:
            return list(session.execute(select(Tenant.id).order_by(Tenant.id)).scalars())

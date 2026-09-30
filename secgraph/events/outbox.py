"""Transactional outbox.

Changes are buffered while a unit of work runs and written in the same
transaction as the change itself, so a committed change always has its event
and a rolled-back change never does. Sequence numbers are allocated under
the per-tenant lock (see ``store.db.lock_tenant``): consumers can resume from
the last sequence they saw and will not miss or reorder events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from secgraph.store.db import lock_tenant
from secgraph.store.models import ChangeEvent, Tenant
from secgraph.store.types import utcnow


@dataclass
class ChangeBuffer:
    events: list[dict[str, Any]] = field(default_factory=list)

    def add(self, kind: str, entity_type: str, entity_id: str, data: dict[str, Any] | None = None) -> None:
        self.events.append({"kind": kind, "entity_type": entity_type, "entity_id": entity_id, "data": data or {}})

    def flush(self, session: Session, tenant_id: str, batch_id: str | None = None) -> int:
        """Write buffered events. Call last in the transaction; returns the new head sequence."""
        if not self.events:
            return 0
        session.flush()
        tenant = lock_tenant(session, tenant_id)
        seq = tenant.change_seq
        now = utcnow()
        rows = []
        for event in self.events:
            seq += 1
            rows.append(
                ChangeEvent(
                    tenant_id=tenant_id,
                    seq=seq,
                    ts=now,
                    kind=event["kind"],
                    entity_type=event["entity_type"],
                    entity_id=event["entity_id"],
                    data=event["data"],
                    batch_id=batch_id,
                )
            )
        session.add_all(rows)
        tenant.change_seq = seq
        self.events.clear()
        return seq


def read_changes(
    session: Session,
    tenant_id: str,
    *,
    after: int = 0,
    limit: int = 500,
    kinds: list[str] | None = None,
    entity_types: list[str] | None = None,
) -> list[ChangeEvent]:
    stmt = select(ChangeEvent).where(ChangeEvent.tenant_id == tenant_id, ChangeEvent.seq > after)
    if kinds:
        stmt = stmt.where(ChangeEvent.kind.in_(kinds))
    if entity_types:
        stmt = stmt.where(ChangeEvent.entity_type.in_(entity_types))
    return list(session.execute(stmt.order_by(ChangeEvent.seq).limit(limit)).scalars())


def head_sequence(session: Session, tenant_id: str) -> int:
    seq = session.execute(select(Tenant.change_seq).where(Tenant.id == tenant_id)).scalar_one_or_none()
    return int(seq or 0)


def prune_changes(session: Session, tenant_id: str, older_than: datetime) -> int:
    result = session.execute(
        delete(ChangeEvent).where(ChangeEvent.tenant_id == tenant_id, ChangeEvent.ts < older_than)
    )
    return int(getattr(result, "rowcount", 0) or 0)


def event_payload(event: ChangeEvent) -> dict[str, Any]:
    return {
        "seq": event.seq,
        "ts": event.ts.isoformat(),
        "kind": event.kind,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "data": event.data,
        "batch_id": event.batch_id,
    }

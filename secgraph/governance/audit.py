"""Tamper-evident audit log.

Each entry's hash is SHA-256(previous hash || canonical JSON of the entry).
Editing, deleting or reordering any entry breaks every later link; ``verify``
walks the chain and reports the first break. Chains are per tenant.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from secgraph.observability import AUDIT_ENTRIES, get_logger, request_id_var
from secgraph.store.db import lock_tenant
from secgraph.store.models import AuditEntry, Tenant
from secgraph.store.types import utcnow

log = get_logger(__name__)
GENESIS = "0" * 64


def _canonical_ts(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_hash(
    prev_hash: str, seq: int, ts: datetime, actor: str, action: str, target: str, detail: dict[str, Any]
) -> str:
    body = json.dumps(
        {"seq": seq, "ts": _canonical_ts(ts), "actor": actor, "action": action, "target": target, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def record(
    session: Session,
    tenant_id: str,
    *,
    actor: str,
    action: str,
    target: str = "",
    detail: dict[str, Any] | None = None,
) -> AuditEntry:
    """Append an entry inside the caller's transaction (commits or rolls back with it)."""
    # Round-trip through JSON so the stored detail and the hashed detail are identical.
    clean_detail = json.loads(json.dumps(detail or {}, default=str))
    session.flush()
    tenant = lock_tenant(session, tenant_id)
    seq = tenant.audit_seq + 1
    now = utcnow()
    ts = now.replace(microsecond=(now.microsecond // 1000) * 1000)  # survives every backend's precision
    digest = compute_hash(tenant.audit_head, seq, ts, actor, action, target, clean_detail)
    entry = AuditEntry(
        tenant_id=tenant_id,
        seq=seq,
        ts=ts,
        actor=actor,
        action=action,
        target=target[:256],
        detail=clean_detail,
        request_id=request_id_var.get(),
        prev_hash=tenant.audit_head,
        hash=digest,
    )
    session.add(entry)
    tenant.audit_seq = seq
    tenant.audit_head = digest
    AUDIT_ENTRIES.labels(action=action).inc()
    log.info("audit", action=action, actor=actor, target=target, audit_seq=seq)
    return entry


def verify(session: Session, tenant_id: str) -> dict[str, Any]:
    """Recompute the whole chain. ``ok`` is False at the first altered, missing or reordered entry."""
    prev = GENESIS
    expected_seq = 1
    count = 0
    last_seq = 0
    while True:
        rows = list(
            session.execute(
                select(AuditEntry)
                .where(AuditEntry.tenant_id == tenant_id, AuditEntry.seq > last_seq)
                .order_by(AuditEntry.seq)
                .limit(2000)
            ).scalars()
        )
        if not rows:
            break
        for row in rows:
            if row.seq != expected_seq:
                return {"ok": False, "entries": count, "broken_at_seq": expected_seq, "reason": "missing entry"}
            digest = compute_hash(prev, row.seq, row.ts, row.actor, row.action, row.target, row.detail)
            if row.prev_hash != prev:
                return {"ok": False, "entries": count, "broken_at_seq": row.seq, "reason": "prev_hash mismatch"}
            if row.hash != digest:
                return {"ok": False, "entries": count, "broken_at_seq": row.seq, "reason": "hash mismatch"}
            prev = row.hash
            expected_seq += 1
            count += 1
            last_seq = row.seq
            session.expunge(row)
    tenant = session.get(Tenant, tenant_id)
    if tenant is not None and (tenant.audit_seq != count or tenant.audit_head != prev):
        return {"ok": False, "entries": count, "broken_at_seq": count + 1, "reason": "chain truncated"}
    return {"ok": True, "entries": count, "head": prev}


def list_entries(
    session: Session, tenant_id: str, *, before: int | None = None, action: str | None = None, limit: int = 100
) -> list[AuditEntry]:
    stmt = select(AuditEntry).where(AuditEntry.tenant_id == tenant_id)
    if before is not None:
        stmt = stmt.where(AuditEntry.seq < before)
    if action:
        stmt = stmt.where(AuditEntry.action == action)
    return list(session.execute(stmt.order_by(AuditEntry.seq.desc()).limit(limit)).scalars())

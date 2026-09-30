"""Webhook subscriptions: push the change feed to downstream products.

Delivery is at-least-once and in order per subscription. Each POST carries a
batch of events, signed with HMAC-SHA256 over ``"<timestamp>.<body>"`` so the
receiver can verify origin and reject replays:

    X-SecGraph-Timestamp: 1790612345
    X-SecGraph-Signature: sha256=<hex>
    X-SecGraph-Delivery:  <uuid>

A subscription that keeps failing backs off exponentially and is disabled
after ``SECGRAPH_WEBHOOK_MAX_ATTEMPTS`` consecutive failures.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import time
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import NotFound, ValidationFailed
from secgraph.events.outbox import event_payload, read_changes
from secgraph.governance import audit
from secgraph.observability import WEBHOOK_DELIVERIES, get_logger
from secgraph.store.db import Database
from secgraph.store.models import Webhook
from secgraph.store.types import utcnow

log = get_logger(__name__)

EVENT_KINDS = (
    "node.created", "node.updated", "node.deleted", "node.merged", "edge.created", "edge.updated", "edge.deleted",
)
_BATCH = 200
_ALWAYS_BLOCKED = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, including cloud metadata endpoints
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
]


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def check_target(url: str, settings: Settings, *, resolve: bool = True) -> None:
    """Refuse webhook targets that could be used to reach somewhere they should not (SSRF)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationFailed("webhook URL must be http(s)://host[:port]/path")
    if parts.username or parts.password:
        raise ValidationFailed("webhook URL must not contain credentials")
    if settings.is_production() and parts.scheme != "https":
        raise ValidationFailed("webhook URL must use https in production")
    host = parts.hostname.lower()
    allowed = settings.webhook_allowed_host_list()
    if allowed and not any(host == a.lower() or host.endswith("." + a.lower().lstrip(".")) for a in allowed):
        raise ValidationFailed(f"host '{host}' is not in SECGRAPH_WEBHOOK_ALLOWED_HOSTS")
    addresses: list[str] = []
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        if resolve:
            try:
                infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
            except socket.gaierror as exc:
                raise ValidationFailed(f"webhook host '{host}' does not resolve") from exc
            addresses = sorted({str(info[4][0]) for info in infos})
    for text in addresses:
        address = ipaddress.ip_address(text)
        if any(address in network for network in _ALWAYS_BLOCKED):
            raise ValidationFailed(f"webhook target {text} is a link-local or reserved address")
        if address.is_loopback and settings.is_production():
            raise ValidationFailed("webhook target must not be a loopback address in production")
        if address.is_private and not address.is_loopback and not settings.webhook_allow_private:
            raise ValidationFailed(
                f"webhook target {text} is a private address; set SECGRAPH_WEBHOOK_ALLOW_PRIVATE=true to allow it"
            )


def _view(hook: Webhook) -> dict[str, Any]:
    return {
        "id": hook.id,
        "name": hook.name,
        "url": hook.url,
        "event_kinds": list(hook.event_kinds or []),
        "entity_types": list(hook.entity_types or []),
        "active": hook.active,
        "cursor": hook.cursor,
        "failures": hook.failures,
        "last_error": hook.last_error,
        "last_delivery_at": hook.last_delivery_at.isoformat() if hook.last_delivery_at else None,
        "next_attempt_at": hook.next_attempt_at.isoformat() if hook.next_attempt_at else None,
        "created_by": hook.created_by,
        "created_at": hook.created_at.isoformat(),
    }


class WebhookService:
    def __init__(self, db: Database, settings: Settings, client: httpx.Client | None = None):
        self.db = db
        self.settings = settings
        self._client = client

    # ------------------------------------------------------------------ #
    def create(
        self,
        tenant_id: str,
        actor: str,
        *,
        name: str,
        url: str,
        event_kinds: list[str] | None = None,
        entity_types: list[str] | None = None,
        from_now: bool = True,
        known_types: set[str] | None = None,
    ) -> dict[str, Any]:
        name = name.strip()
        if not 1 <= len(name) <= 128:
            raise ValidationFailed("name must be 1-128 characters")
        if len(url) > 1024:
            raise ValidationFailed("url is limited to 1024 characters")
        check_target(url, self.settings)
        kinds = list(dict.fromkeys(event_kinds or []))
        unknown = sorted(set(kinds) - set(EVENT_KINDS))
        if unknown:
            raise ValidationFailed(f"unknown event kind(s): {', '.join(unknown)}; known: {', '.join(EVENT_KINDS)}")
        types = list(dict.fromkeys(entity_types or []))
        if known_types is not None:
            bad = sorted(set(types) - known_types)
            if bad:
                raise ValidationFailed(f"unknown node or edge type(s): {', '.join(bad)}")
        secret = secrets.token_urlsafe(32)
        hook_id = uuid.uuid4().hex

        def _work(session: Session) -> dict[str, Any]:
            from secgraph.events.outbox import head_sequence
            from secgraph.store.db import ensure_tenant

            ensure_tenant(session, tenant_id)
            hook = Webhook(
                id=hook_id,
                tenant_id=tenant_id,
                name=name,
                url=url,
                secret=secret,
                event_kinds=kinds,
                entity_types=types,
                cursor=head_sequence(session, tenant_id) if from_now else 0,
                created_by=actor,
            )
            session.add(hook)
            audit.record(
                session, tenant_id, actor=actor, action="webhook.create", target=f"webhook:{hook_id}",
                detail={"name": name, "url": url, "event_kinds": kinds, "entity_types": types},
            )
            session.flush()
            return _view(hook)

        view = self.db.run(_work)
        view["secret"] = secret  # shown once
        return view

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.db.transaction() as session:
            rows = session.execute(
                select(Webhook).where(Webhook.tenant_id == tenant_id).order_by(Webhook.created_at)
            ).scalars()
            return [_view(h) for h in rows]

    def delete(self, tenant_id: str, actor: str, hook_id: str) -> None:
        def _work(session: Session) -> None:
            hook = session.execute(
                select(Webhook).where(Webhook.tenant_id == tenant_id, Webhook.id == hook_id)
            ).scalar_one_or_none()
            if hook is None:
                raise NotFound(f"webhook {hook_id} does not exist")
            session.delete(hook)
            audit.record(session, tenant_id, actor=actor, action="webhook.delete", target=f"webhook:{hook_id}")

        self.db.run(_work)

    def set_active(self, tenant_id: str, actor: str, hook_id: str, active: bool) -> dict[str, Any]:
        def _work(session: Session) -> dict[str, Any]:
            hook = session.execute(
                select(Webhook).where(Webhook.tenant_id == tenant_id, Webhook.id == hook_id)
            ).scalar_one_or_none()
            if hook is None:
                raise NotFound(f"webhook {hook_id} does not exist")
            hook.active = active
            if active:
                hook.failures = 0
                hook.next_attempt_at = None
                hook.last_error = None
            audit.record(
                session, tenant_id, actor=actor, action="webhook.enable" if active else "webhook.disable",
                target=f"webhook:{hook_id}",
            )
            return _view(hook)

        return self.db.run(_work)

    # ------------------------------------------------------------------ #
    # Delivery (worker)
    # ------------------------------------------------------------------ #
    def deliver_pending(self) -> dict[str, int]:
        """One delivery pass over every due subscription. Returns counters."""
        stats = {"delivered": 0, "failed": 0, "events": 0}
        now = utcnow()
        with self.db.transaction() as session:
            due = list(
                session.execute(
                    select(Webhook.id).where(
                        Webhook.active.is_(True),
                        or_(Webhook.next_attempt_at.is_(None), Webhook.next_attempt_at <= now),
                    )
                ).scalars()
            )
        for hook_id in due:
            try:
                outcome = self.db.run(lambda s, h=hook_id: self._deliver_one(s, h), attempts=1)
            except Exception:
                log.error("webhook delivery pass failed", webhook=hook_id, exc_info=True)
                continue
            for key, value in outcome.items():
                stats[key] += value
        return stats

    def _deliver_one(self, session: Session, hook_id: str) -> dict[str, int]:
        hook = session.execute(
            select(Webhook).where(Webhook.id == hook_id).with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if hook is None or not hook.active:
            return {"delivered": 0, "failed": 0, "events": 0}
        events = read_changes(session, hook.tenant_id, after=hook.cursor, limit=_BATCH)
        if not events:
            return {"delivered": 0, "failed": 0, "events": 0}
        kinds, types = set(hook.event_kinds or []), set(hook.entity_types or [])
        wanted = [
            e for e in events if (not kinds or e.kind in kinds) and (not types or e.entity_type in types)
        ]
        last_seq = events[-1].seq
        if not wanted:
            hook.cursor = last_seq
            return {"delivered": 0, "failed": 0, "events": 0}
        body = json.dumps(
            {
                "webhook_id": hook.id,
                "tenant": hook.tenant_id,
                "previous_cursor": hook.cursor,
                "cursor": last_seq,
                "gap": events[0].seq > hook.cursor + 1,  # events were pruned before they could be delivered
                "events": [event_payload(e) for e in wanted],
            },
            separators=(",", ":"),
            default=str,
        ).encode()
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "security-graph-webhook/1",
            "X-SecGraph-Timestamp": timestamp,
            "X-SecGraph-Signature": sign(hook.secret, timestamp, body),
            "X-SecGraph-Delivery": uuid.uuid4().hex,
        }
        error: str | None = None
        try:
            check_target(hook.url, self.settings)  # re-checked at send time: DNS may have changed
            client = self._client or httpx.Client(timeout=self.settings.webhook_timeout_s, follow_redirects=False)
            try:
                response = client.post(hook.url, content=body, headers=headers)
            finally:
                if self._client is None:
                    client.close()
            if not 200 <= response.status_code < 300:
                error = f"HTTP {response.status_code}"
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:300]}"
        now = utcnow()
        if error is None:
            hook.cursor = last_seq
            hook.failures = 0
            hook.last_error = None
            hook.next_attempt_at = None
            hook.last_delivery_at = now
            WEBHOOK_DELIVERIES.labels(outcome="delivered").inc()
            return {"delivered": 1, "failed": 0, "events": len(wanted)}
        hook.failures += 1
        hook.last_error = error
        WEBHOOK_DELIVERIES.labels(outcome="failed").inc()
        if hook.failures >= self.settings.webhook_max_attempts:
            hook.active = False
            audit.record(
                session, hook.tenant_id, actor="system:worker", action="webhook.disabled",
                target=f"webhook:{hook.id}", detail={"failures": hook.failures, "last_error": error},
            )
            log.error("webhook disabled after repeated failures", webhook=hook.id, error=error)
        else:
            delay = min(5 * 2 ** (hook.failures - 1), 3600)
            hook.next_attempt_at = now + timedelta(seconds=delay)
            log.warning("webhook delivery failed", webhook=hook.id, error=error, retry_in_seconds=delay)
        return {"delivered": 0, "failed": 1, "events": 0}

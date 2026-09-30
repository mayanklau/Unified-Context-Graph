"""Background worker: webhook delivery and graph maintenance.

Run one or more with ``secgraph worker``. Webhook rows are locked while they
are delivered, so several workers cooperate without double delivery.
Maintenance (expiry, retention) is idempotent; running it twice is harmless.
"""

from __future__ import annotations

import signal
import threading
import time
from typing import Any

from secgraph.context import AppContext
from secgraph.observability import get_logger

log = get_logger(__name__)


def run_maintenance(ctx: AppContext) -> dict[str, Any]:
    """Expire stale graph elements, apply retention and archive expired notes, for every tenant."""
    totals = {"tenants": 0, "nodes_expired": 0, "edges_expired": 0, "change_events_pruned": 0,
              "versions_pruned": 0, "notes_archived": 0}
    for tenant_id in ctx.curation.tenants():
        try:
            expired = ctx.curation.expire_stale(tenant_id)
            pruned = ctx.curation.prune_history(tenant_id)
            archived = ctx.memory.expire(tenant_id)
        except Exception:
            log.error("maintenance failed for tenant", tenant=tenant_id, exc_info=True)
            continue
        totals["tenants"] += 1
        totals["nodes_expired"] += expired["nodes"]
        totals["edges_expired"] += expired["edges"]
        totals["change_events_pruned"] += pruned["change_events"]
        totals["versions_pruned"] += pruned["node_versions"] + pruned["edge_versions"]
        totals["notes_archived"] += archived
    return totals


def run_once(ctx: AppContext) -> dict[str, Any]:
    return {"webhooks": ctx.webhooks.deliver_pending(), "maintenance": run_maintenance(ctx)}


def run_forever(ctx: AppContext, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()

    def _stop(_signum: int, _frame: Any) -> None:
        log.info("worker stopping")
        stop.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
    log.info("worker started", interval=ctx.settings.worker_interval_seconds)
    next_maintenance = 0.0
    while not stop.is_set():
        try:
            stats = ctx.webhooks.deliver_pending()
            if stats["delivered"] or stats["failed"]:
                log.info("webhook pass", **stats)
        except Exception:
            log.error("webhook pass failed", exc_info=True)
        if time.monotonic() >= next_maintenance:
            try:
                totals = run_maintenance(ctx)
                log.info("maintenance pass", **totals)
            except Exception:
                log.error("maintenance pass failed", exc_info=True)
            next_maintenance = time.monotonic() + ctx.settings.maintenance_interval_seconds
        stop.wait(ctx.settings.worker_interval_seconds)
    log.info("worker stopped")

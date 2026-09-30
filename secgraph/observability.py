"""Structured logging and Prometheus metrics.

Logs are single-line JSON with a request/trace id so they can be shipped to
the platform SIEM unchanged. Metrics are exposed at ``/metrics``.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
tenant_var: contextvars.ContextVar[str] = contextvars.ContextVar("tenant", default="-")
principal_var: contextvars.ContextVar[str] = contextvars.ContextVar("principal", default="-")

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
            "tenant": tenant_var.get(),
            "principal": principal_var.get(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class _KVAdapter(logging.LoggerAdapter):  # type: ignore[type-arg]
    """``log.info("event", key=value)`` — keyword arguments become JSON fields."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra = kwargs.pop("extra", {}) or {}
        std = {k: kwargs.pop(k) for k in ("exc_info", "stack_info", "stacklevel") if k in kwargs}
        extra.update(kwargs)
        return msg, {"extra": extra, **std}


def get_logger(name: str) -> _KVAdapter:
    return _KVAdapter(logging.getLogger(name), {})


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
REGISTRY = CollectorRegistry()

HTTP_REQUESTS = Counter(
    "secgraph_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=REGISTRY
)
HTTP_LATENCY = Histogram(
    "secgraph_http_request_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    registry=REGISTRY,
)
INGEST_RECORDS = Counter(
    "secgraph_ingest_records_total",
    "Records processed by ingestion",
    ["kind", "outcome"],  # kind: node|edge ; outcome: created|updated|unchanged|deleted|quarantined
    registry=REGISTRY,
)
INGEST_BATCH_SECONDS = Histogram(
    "secgraph_ingest_batch_seconds",
    "Ingest batch duration",
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60, 300),
    registry=REGISTRY,
)
RESOLUTION_CONFLICTS = Counter(
    "secgraph_resolution_conflicts_total", "Entity-resolution conflicts recorded", registry=REGISTRY
)
QUERY_SECONDS = Histogram(
    "secgraph_query_seconds",
    "Graph query duration",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 30),
    registry=REGISTRY,
)
ANALYTICS_SECONDS = Histogram(
    "secgraph_analytics_seconds",
    "Analytics duration",
    ["operation"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60),
    registry=REGISTRY,
)
ANALYTICS_CACHE = Counter(
    "secgraph_analytics_cache_total", "Attack-graph projection cache", ["result"], registry=REGISTRY
)
AUTH_EVENTS = Counter("secgraph_auth_events_total", "Authentication events", ["outcome"], registry=REGISTRY)
RATE_LIMITED = Counter("secgraph_rate_limited_total", "Requests rejected by rate limiting", registry=REGISTRY)
AUDIT_ENTRIES = Counter("secgraph_audit_entries_total", "Audit entries written", ["action"], registry=REGISTRY)
WEBHOOK_DELIVERIES = Counter(
    "secgraph_webhook_deliveries_total", "Webhook delivery attempts", ["outcome"], registry=REGISTRY
)
MEMORY_NOTES = Counter("secgraph_memory_notes_total", "Agent memory notes written", ["kind"], registry=REGISTRY)
MCP_CALLS = Counter("secgraph_mcp_tool_calls_total", "MCP tool calls", ["tool", "outcome"], registry=REGISTRY)
GUARDRAIL_DECISIONS = Counter(
    "secgraph_guardrail_decisions_total", "Protective-plane decisions", ["stage", "decision"], registry=REGISTRY
)
GRAPH_NODES = Gauge("secgraph_nodes", "Current nodes by tenant and type", ["tenant", "type"], registry=REGISTRY)
GRAPH_EDGES = Gauge("secgraph_edges", "Current edges by tenant and type", ["tenant", "type"], registry=REGISTRY)
QUARANTINE_OPEN = Gauge("secgraph_quarantine_open", "Open quarantined records", ["tenant"], registry=REGISTRY)


@contextmanager
def timed(histogram: Histogram, **labels: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        (histogram.labels(**labels) if labels else histogram).observe(time.perf_counter() - start)

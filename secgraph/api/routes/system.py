"""Liveness, readiness, metrics and the identity of the caller."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select

from secgraph import __version__
from secgraph.api.deps import Caller, Ctx
from secgraph.api.schemas import LoginBody
from secgraph.errors import AuthenticationError
from secgraph.observability import GRAPH_EDGES, GRAPH_NODES, QUARANTINE_OPEN, REGISTRY
from secgraph.store.models import Edge, Node, QuarantinedRecord

router = APIRouter()


@router.get("/health", tags=["system"], summary="Liveness")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/ready", tags=["system"], summary="Readiness: database reachable, ontology loaded")
def ready(ctx: Ctx, response: Response) -> dict[str, Any]:
    database = ctx.db.ping()
    if not database:
        response.status_code = 503
    return {
        "status": "ready" if database else "unavailable",
        "database": "ok" if database else "unreachable",
        "ontology": {"name": ctx.ontology.name, "version": ctx.ontology.version},
        "version": __version__,
    }


@router.get("/metrics", tags=["system"], summary="Prometheus metrics", include_in_schema=False)
def metrics(ctx: Ctx, request: Request) -> Response:
    token = ctx.settings.metrics_token
    if token:
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
            raise AuthenticationError("metrics require the configured bearer token")
    # Gauges are refreshed on scrape; the queries are index-only aggregates.
    with ctx.db.snapshot() as session:
        GRAPH_NODES.clear()
        for tenant, node_type, count in session.execute(
            select(Node.tenant_id, Node.type, func.count()).where(Node.deleted_at.is_(None)).group_by(
                Node.tenant_id, Node.type
            )
        ):
            GRAPH_NODES.labels(tenant=tenant, type=node_type).set(count)
        GRAPH_EDGES.clear()
        for tenant, edge_type, count in session.execute(
            select(Edge.tenant_id, Edge.type, func.count()).where(Edge.valid_to.is_(None)).group_by(
                Edge.tenant_id, Edge.type
            )
        ):
            GRAPH_EDGES.labels(tenant=tenant, type=edge_type).set(count)
        QUARANTINE_OPEN.clear()
        for tenant, count in session.execute(
            select(QuarantinedRecord.tenant_id, func.count()).where(QuarantinedRecord.status == "open").group_by(
                QuarantinedRecord.tenant_id
            )
        ):
            QUARANTINE_OPEN.labels(tenant=tenant).set(count)
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@router.post("/api/v1/auth/token", tags=["auth"], summary="Exchange a username and password for a bearer token")
def login(body: LoginBody, ctx: Ctx, request: Request) -> dict[str, Any]:
    client = request.client.host if request.client else "unknown"
    ctx.login_limiter.check(f"login:{client}:{body.username.strip().lower()}")
    return ctx.auth.login(body.username, body.password)


@router.get("/api/v1/auth/me", tags=["auth"], summary="Who am I, and what may I do")
def me(principal: Caller) -> dict[str, Any]:
    return {
        "id": principal.id,
        "name": principal.name,
        "kind": principal.kind,
        "tenant": principal.tenant_id,
        "roles": list(principal.roles),
        "permissions": sorted(principal.permissions),
        "node_types": sorted(principal.node_types) if principal.node_types is not None else None,
    }

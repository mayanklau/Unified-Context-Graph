"""Attack-path analytics."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from secgraph.api.deps import AsOf, Ctx, require_analytics
from secgraph.governance.rbac import Principal

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])
Analyst = Annotated[Principal, Depends(require_analytics)]


@router.get("/overview", summary="Entry points, crown jewels at risk, expected impact")
def overview(
    ctx: Ctx, principal: Analyst, as_of: AsOf, limit: Annotated[int, Query(ge=1, le=100)] = 10, estimate: bool = True
) -> dict[str, Any]:
    return ctx.analytics.overview(principal.tenant_id, principal.scope, limit=limit, estimate=estimate, as_of=as_of)


@router.get("/attack-paths", summary="Most probable attack paths, every step explained")
def attack_paths(
    ctx: Ctx,
    principal: Analyst,
    as_of: AsOf,
    target_id: str | None = None,
    source_id: str | None = None,
    k: Annotated[int, Query(ge=1, le=25)] = 5,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> dict[str, Any]:
    return ctx.analytics.attack_paths(
        principal.tenant_id, principal.scope, target_id=target_id, source_id=source_id, k=k, limit=limit, as_of=as_of
    )


@router.get("/nodes/{node_id}/exposure", summary="How exposed one entity is, through what, leading where")
def exposure(node_id: str, ctx: Ctx, principal: Analyst, as_of: AsOf) -> dict[str, Any]:
    return ctx.analytics.node_exposure(principal.tenant_id, principal.scope, node_id, as_of=as_of)


@router.get("/nodes/{node_id}/blast-radius", summary="Assume compromise: what is reachable, which services suffer")
def blast_radius(
    node_id: str,
    ctx: Ctx,
    principal: Analyst,
    as_of: AsOf,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    min_probability: Annotated[float, Query(ge=0, le=1)] = 0.01,
) -> dict[str, Any]:
    return ctx.analytics.blast_radius(
        principal.tenant_id, principal.scope, node_id, limit=limit, min_probability=min_probability, as_of=as_of
    )


@router.get("/remediation-priorities", summary="Fixes ranked by the crown-jewel risk each removes")
def remediation_priorities(
    ctx: Ctx,
    principal: Analyst,
    as_of: AsOf,
    by: Annotated[str, Query(pattern="^(finding|vulnerability|asset)$")] = "finding",
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    time_budget_s: Annotated[float, Query(gt=0, le=60)] = 10.0,
) -> dict[str, Any]:
    return ctx.analytics.remediation_priorities(
        principal.tenant_id, principal.scope, by=by, limit=limit, time_budget_s=time_budget_s, as_of=as_of
    )


@router.get("/choke-points", summary="Where one control protects the most crown jewels")
def choke_points(
    ctx: Ctx, principal: Analyst, as_of: AsOf, limit: Annotated[int, Query(ge=1, le=100)] = 10
) -> dict[str, Any]:
    return ctx.analytics.choke_points(principal.tenant_id, principal.scope, limit=limit, as_of=as_of)


@router.get("/detection-race", summary="Does the attacker reach a crown jewel before being detected?")
def detection_race(ctx: Ctx, principal: Analyst, as_of: AsOf, target_id: str | None = None) -> dict[str, Any]:
    return ctx.analytics.detection_race(principal.tenant_id, principal.scope, target_id=target_id, as_of=as_of)


@router.get("/parameters", summary="The model in full: every rule, weight and formula behind the numbers")
def parameters(ctx: Ctx, principal: Analyst) -> dict[str, Any]:
    return ctx.analytics.parameters()

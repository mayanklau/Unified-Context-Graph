"""Write the graph: canonical batches, source-native files, curation."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select

from secgraph.api.deps import Ctx, require
from secgraph.api.schemas import IdsBody, MergeBody, ResolveBody
from secgraph.errors import ValidationFailed
from secgraph.governance.rbac import Principal
from secgraph.ingest.canonical import IngestRequest
from secgraph.ingest.pipeline import ingest_source
from secgraph.store.models import IngestBatch

router = APIRouter(prefix="/api/v1", tags=["ingest"])
Writer = Annotated[Principal, Depends(require("graph:write"))]
Curator = Annotated[Principal, Depends(require("graph:curate"))]


@router.post("/ingest", summary="Ingest a batch of canonical node and edge records")
def ingest(body: IngestRequest, ctx: Ctx, principal: Writer) -> dict[str, Any]:
    result = ctx.ingest.ingest(principal.tenant_id, principal.id, body)
    return result.to_dict()


@router.get("/ingest/mappings", summary="Source formats this deployment can ingest directly")
def mappings(ctx: Ctx, principal: Writer) -> dict[str, Any]:
    return {"items": ctx.mappings.describe()}


@router.post(
    "/ingest/source/{mapping}",
    summary="Ingest a source-native file (CSV or JSON) through a named mapping",
    description="Send the file as the request body. Mapping parameters go in the query string as `param.<name>=…`.",
)
async def ingest_mapped(
    mapping: str,
    request: Request,
    ctx: Ctx,
    principal: Writer,
    source: Annotated[str | None, Query(description="Override the mapping's default source name")] = None,
) -> dict[str, Any]:
    params = {key[len("param.") :]: value for key, value in request.query_params.items() if key.startswith("param.")}
    payload = await request.body()
    if not payload:
        raise ValidationFailed("the request body is empty; send the source file as the body")
    return await run_in_threadpool(
        ingest_source,
        ctx.ingest,
        ctx.mappings,
        ctx.settings,
        principal.tenant_id,
        principal.id,
        mapping,
        payload,
        params=params,
        source=source,
    )


@router.get("/ingest/batches", summary="Recent ingest batches")
def batches(ctx: Ctx, principal: Writer, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        rows = session.execute(
            select(IngestBatch)
            .where(IngestBatch.tenant_id == principal.tenant_id)
            .order_by(IngestBatch.started_at.desc())
            .limit(limit)
        ).scalars()
        return {
            "items": [
                {
                    "id": b.id,
                    "source": b.source,
                    "mapping": b.mapping,
                    "status": b.status,
                    "counts": b.counts,
                    "ontology_version": b.ontology_version,
                    "principal": b.principal,
                    "started_at": b.started_at.isoformat(),
                    "finished_at": b.finished_at.isoformat() if b.finished_at else None,
                    "error": b.error,
                }
                for b in rows
            ]
        }


# ---- curation ---------------------------------------------------------------
@router.get("/quarantine", tags=["curation"], summary="Records that failed validation")
def quarantine(
    ctx: Ctx,
    principal: Curator,
    status: Annotated[str, Query(pattern="^(open|replayed|discarded|all)$")] = "open",
    batch_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    rows, total = ctx.curation.list_quarantine(
        principal.tenant_id, status=status, batch_id=batch_id, limit=limit, offset=offset
    )
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "batch_id": r.batch_id,
                "source": r.source,
                "kind": r.kind,
                "reason": r.reason,
                "record": r.record,
                "status": r.status,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.post("/quarantine/replay", tags=["curation"], summary="Re-ingest quarantined records")
def replay(body: IdsBody, ctx: Ctx, principal: Curator) -> dict[str, Any]:
    principal.require("graph:write")
    return ctx.curation.replay_quarantine(principal.tenant_id, principal.id, body.ids)


@router.post("/quarantine/discard", tags=["curation"], summary="Discard quarantined records")
def discard(body: IdsBody, ctx: Ctx, principal: Curator) -> dict[str, Any]:
    return {"discarded": ctx.curation.discard_quarantine(principal.tenant_id, principal.id, body.ids)}


@router.get("/conflicts", tags=["curation"], summary="Entity-resolution conflicts awaiting a decision")
def conflicts(
    ctx: Ctx,
    principal: Curator,
    status: Annotated[str, Query(pattern="^(open|resolved|dismissed|all)$")] = "open",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    rows, total = ctx.curation.list_conflicts(principal.tenant_id, status=status, limit=limit, offset=offset)
    return {
        "total": total,
        "items": [
            {
                "id": c.id,
                "node_type": c.node_type,
                "reason": c.reason,
                "node_ids": c.node_ids,
                "detail": c.detail,
                "occurrences": c.occurrences,
                "status": c.status,
                "first_seen": c.first_seen.isoformat(),
                "last_seen": c.last_seen.isoformat(),
            }
            for c in rows
        ],
    }


@router.post("/conflicts/{conflict_id}/dismiss", tags=["curation"], summary="Mark a conflict as not a duplicate")
def dismiss_conflict(conflict_id: str, ctx: Ctx, principal: Curator) -> dict[str, str]:
    ctx.curation.dismiss_conflict(principal.tenant_id, principal.id, conflict_id)
    return {"status": "dismissed"}


@router.post(
    "/conflicts/{conflict_id}/resolve",
    tags=["curation"],
    summary="Settle a conflict by naming the entity the records belong to",
)
def resolve_conflict(conflict_id: str, body: ResolveBody, ctx: Ctx, principal: Curator) -> dict[str, Any]:
    return ctx.curation.resolve_conflict(principal.tenant_id, principal.id, conflict_id, body.node_id)


@router.post("/nodes/merge", tags=["curation"], summary="Merge a duplicate entity into a survivor")
def merge(body: MergeBody, ctx: Ctx, principal: Curator) -> dict[str, Any]:
    return ctx.curation.merge_nodes(principal.tenant_id, principal.id, body.survivor_id, body.duplicate_id)

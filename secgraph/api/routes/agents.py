"""The agent-facing surface: context packs, shared memory, MCP."""

from __future__ import annotations

import json
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from secgraph.agents.mcp import INVALID_REQUEST, PARSE_ERROR, PROTOCOL_VERSIONS
from secgraph.api.deps import AsOf, Caller, Ctx, csv_param, require
from secgraph.api.schemas import FeedbackBody, NoteBody, SuggestBody
from secgraph.errors import PermissionDenied
from secgraph.governance.rbac import Principal

router = APIRouter(tags=["agents"])
Reader = Annotated[Principal, Depends(require("graph:read"))]
MemoryReader = Annotated[Principal, Depends(require("memory:read"))]
MemoryWriter = Annotated[Principal, Depends(require("memory:write"))]


@router.get("/api/v1/context/{node_id}", summary="Token-budgeted briefing on one entity")
def context(
    node_id: str,
    ctx: Ctx,
    principal: Reader,
    as_of: AsOf,
    budget_tokens: Annotated[int | None, Query(ge=200)] = None,
    include_analytics: bool = True,
) -> dict[str, Any]:
    return ctx.context.build(
        principal.tenant_id,
        principal,
        node_id,
        budget_tokens=budget_tokens,
        include_analytics=include_analytics,
        as_of=as_of,
    )


@router.post("/api/v1/memory", summary="Write a note to shared memory", status_code=201)
def remember(body: NoteBody, ctx: Ctx, principal: MemoryWriter) -> dict[str, Any]:
    return ctx.memory.remember(
        principal.tenant_id,
        principal,
        kind=body.kind,
        title=body.title,
        body=body.body,
        entity_ids=body.entity_ids,
        tags=body.tags,
        signature=body.signature,
        confidence=body.confidence,
        supersedes=body.supersedes,
        ttl_days=body.ttl_days,
    )


@router.get("/api/v1/memory", summary="Search shared memory")
def search_memory(
    ctx: Ctx,
    principal: MemoryReader,
    q: Annotated[str | None, Query(max_length=1000)] = None,
    entity_id: str | None = None,
    kind: str | None = None,
    tags: Annotated[str | None, Query(description="Comma-separated tags; all must match")] = None,
    include_archived: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> dict[str, Any]:
    notes = ctx.memory.search(
        principal.tenant_id,
        principal.scope,
        query=q,
        entity_id=entity_id,
        kind=kind,
        tags=csv_param(tags),
        include_archived=include_archived,
        limit=limit,
    )
    return {"items": notes, "total": len(notes)}


@router.post("/api/v1/memory/suggest", summary="Notes from similar situations, best-proven first")
def suggest(body: SuggestBody, ctx: Ctx, principal: MemoryReader) -> dict[str, Any]:
    kinds = tuple(body.kinds) if body.kinds else ("lesson", "playbook", "decision")
    notes = ctx.memory.suggest(
        principal.tenant_id,
        principal.scope,
        entity_ids=body.entity_ids,
        signature=body.signature,
        text=body.text,
        kinds=kinds,
        limit=body.limit,
    )
    return {"items": notes, "total": len(notes)}


@router.get("/api/v1/memory/{note_id}", summary="One note")
def get_note(note_id: str, ctx: Ctx, principal: MemoryReader) -> dict[str, Any]:
    return ctx.memory.get(principal.tenant_id, principal.scope, note_id)


@router.post("/api/v1/memory/{note_id}/feedback", summary="Record that a note was used and whether it worked")
def feedback(note_id: str, body: FeedbackBody, ctx: Ctx, principal: MemoryWriter) -> dict[str, Any]:
    return ctx.memory.feedback(principal.tenant_id, principal, note_id, body.outcome)


@router.delete("/api/v1/memory/{note_id}", summary="Archive a note", status_code=204)
def archive(note_id: str, ctx: Ctx, principal: MemoryWriter) -> Response:
    ctx.memory.archive(principal.tenant_id, principal, note_id)
    return Response(status_code=204)


# ---- Model Context Protocol (Streamable HTTP, JSON responses) ---------------
def _check_origin(request: Request, allowed: list[str]) -> None:
    """Browsers send Origin; a mismatched one means a web page is trying to reach this server (DNS rebinding)."""
    origin = request.headers.get("origin")
    if not origin:
        return
    if origin in allowed:
        return
    host = request.headers.get("host", "")
    if urlsplit(origin).netloc == host:
        return
    raise PermissionDenied("origin not allowed")


@router.post("/mcp", summary="Model Context Protocol endpoint", include_in_schema=False)
async def mcp(request: Request, ctx: Ctx, principal: Caller) -> Response:
    _check_origin(request, ctx.settings.cors_origin_list())
    version = request.headers.get("mcp-protocol-version")
    if version and version not in PROTOCOL_VERSIONS:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": INVALID_REQUEST, "message": f"unsupported MCP-Protocol-Version: {version}"},
            },
            status_code=400,
        )
    raw = await request.body()
    try:
        message = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "invalid JSON"}},
            status_code=400,
        )
    response = await run_in_threadpool(ctx.mcp.handle, message, principal)
    if response is None:
        return Response(status_code=202)
    return JSONResponse(response)


@router.get("/mcp", include_in_schema=False)
def mcp_stream(principal: Caller) -> Response:
    # This server answers every request with a single JSON response and offers no server-initiated stream.
    return Response(status_code=405, headers={"Allow": "POST"})

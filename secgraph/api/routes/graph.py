"""Read the graph: ontology, entities, relationships, queries."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from secgraph.api.deps import AsOf, Ctx, as_of_param, csv_param, json_param, require
from secgraph.api.schemas import MatchBody, PathBody, SubgraphBody
from secgraph.errors import NotFound, ValidationFailed
from secgraph.governance.rbac import Principal
from secgraph.query.views import Viewer
from secgraph.store.repository import GraphReader

router = APIRouter(prefix="/api/v1", tags=["graph"])
Reader = Annotated[Principal, Depends(require("graph:read"))]


@router.get("/ontology", summary="The ontology this graph enforces")
def ontology(ctx: Ctx, principal: Reader) -> dict[str, Any]:
    document = ctx.ontology.model_dump(mode="json")
    document["fingerprint"] = ctx.ontology.fingerprint()
    return document


@router.get("/stats", summary="Node and edge counts by type")
def stats(ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.stats(session, principal.tenant_id, principal.scope)


@router.get("/nodes", summary="Search entities")
def search_nodes(
    ctx: Ctx,
    principal: Reader,
    q: Annotated[str | None, Query(description="Text matched against names and identifiers", max_length=256)] = None,
    type: Annotated[str | None, Query(description="Comma-separated node types")] = None,
    where: Annotated[
        str | None,
        Query(description='Property predicate as JSON, e.g. {"internet_exposed": true, "criticality": {"gte": 4}}'),
    ] = None,
    include_stubs: bool = True,
    limit: Annotated[int | None, Query(ge=1)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    predicate = json_param("where", where)
    if predicate is not None and not isinstance(predicate, dict):
        raise ValidationFailed("'where' must be a JSON object")
    with ctx.db.snapshot() as session:
        return ctx.query.search(
            session,
            principal.tenant_id,
            principal.scope,
            types=csv_param(type),
            text=q,
            where=predicate,
            include_stubs=include_stubs,
            limit=limit,
            offset=offset,
        )


@router.get("/lookup", summary="Find entities by an identifier (hostname, IP, CVE, account, …)")
def lookup(
    ctx: Ctx,
    principal: Reader,
    value: Annotated[str, Query(min_length=1, max_length=512)],
    type: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        found = ctx.query.find_by_identifier(
            session, principal.tenant_id, principal.scope, value=value, node_type=type, kind=kind
        )
    return {"items": found, "total": len(found)}


@router.get("/nodes/{node_id}", summary="One entity, with identifiers and degree")
def get_node(node_id: str, ctx: Ctx, principal: Reader, as_of: AsOf) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.get_node(session, principal.tenant_id, node_id, principal.scope, as_of=as_of)


@router.get("/nodes/{node_id}/history", summary="Every version of an entity")
def node_history(node_id: str, ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return {"versions": ctx.query.history(session, principal.tenant_id, node_id, principal.scope)}


@router.get("/nodes/{node_id}/neighbors", summary="Directly related entities")
def neighbors(
    node_id: str,
    ctx: Ctx,
    principal: Reader,
    as_of: AsOf,
    direction: Annotated[str, Query(pattern="^(out|in|both)$")] = "both",
    edge_type: Annotated[str | None, Query(description="Comma-separated edge types")] = None,
    node_type: Annotated[str | None, Query(description="Comma-separated node types")] = None,
    limit: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.neighbors(
            session,
            principal.tenant_id,
            node_id,
            principal.scope,
            direction=direction,
            edge_types=csv_param(edge_type),
            node_types=csv_param(node_type),
            limit=limit,
            as_of=as_of,
        )


@router.get("/edges/{edge_id}", summary="One relationship and its version history")
def get_edge(edge_id: str, ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        reader = GraphReader(session, principal.tenant_id)
        versions = reader.edge_history(edge_id)
        if not versions:
            raise NotFound(f"edge {edge_id} does not exist")
        ends = reader.get_nodes([versions[0].source, versions[0].target], include_deleted=True)
        if any(not principal.scope.allows(node.type) for node in ends.values()) or len(ends) < 2:
            raise NotFound(f"edge {edge_id} does not exist")
        viewer = Viewer(ctx.ontology, principal.scope)
        return {
            "edge": viewer.edge(versions[0]),
            "current": versions[0].valid_to is None,
            "source": viewer.node(ends[versions[0].source], brief=True),
            "target": viewer.node(ends[versions[0].target], brief=True),
            "versions": [viewer.edge(v) for v in versions],
        }


@router.post("/query/subgraph", summary="Expand a neighbourhood from seed nodes")
def subgraph(body: SubgraphBody, ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.subgraph(
            session,
            principal.tenant_id,
            body.seeds,
            principal.scope,
            depth=body.depth,
            direction=body.direction,
            edge_types=body.edge_types,
            max_nodes=body.max_nodes,
            as_of=as_of_param(body.as_of),
        )


@router.post("/query/path", summary="Shortest path between two entities")
def shortest_path(body: PathBody, ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.shortest_path(
            session,
            principal.tenant_id,
            body.source_id,
            body.target_id,
            principal.scope,
            max_depth=body.max_depth,
            edge_types=body.edge_types,
            directed=body.directed,
            as_of=as_of_param(body.as_of),
        )


@router.post("/query/match", summary="Match a path pattern")
def match(body: MatchBody, ctx: Ctx, principal: Reader) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return ctx.query.match(
            session, principal.tenant_id, body.pattern, principal.scope, as_of=as_of_param(body.as_of)
        )

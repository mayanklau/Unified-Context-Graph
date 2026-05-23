from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ucg.api.dependencies import get_graph_repository
from ucg.graph.models import GraphContext, GraphNode, GraphPath
from ucg.graph.repository import GraphRepository

router = APIRouter()


@router.get("/nodes/{node_id}", response_model=GraphNode)
def get_node(
    node_id: str,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
    tenant_id: str = Query("default"),
) -> GraphNode:
    node = repository.get_node(node_id=node_id, tenant_id=tenant_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.get("/nodes/{node_id}/context", response_model=GraphContext)
def get_context(
    node_id: str,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
    depth: int = Query(1, ge=1, le=5),
    tenant_id: str = Query("default"),
) -> GraphContext:
    context = repository.context(node_id=node_id, tenant_id=tenant_id, depth=depth)
    if not context.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    return context


@router.get("/paths", response_model=list[GraphPath])
def get_paths(
    source_id: str,
    target_id: str,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
    tenant_id: str = Query("default"),
    max_depth: int = Query(4, ge=1, le=8),
) -> list[GraphPath]:
    return repository.paths(
        source_id=source_id,
        target_id=target_id,
        tenant_id=tenant_id,
        max_depth=max_depth,
    )

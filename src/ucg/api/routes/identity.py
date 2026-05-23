from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ucg.api.dependencies import get_graph_repository
from ucg.graph.models import GraphContext
from ucg.graph.repository import GraphRepository

router = APIRouter()


@router.get("/{identity_id}/context", response_model=GraphContext)
def identity_context(
    identity_id: str,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
    tenant_id: str = Query("default"),
) -> GraphContext:
    context = repository.context(node_id=identity_id, tenant_id=tenant_id, depth=2)
    if not context.nodes:
        raise HTTPException(status_code=404, detail="Identity not found")
    return context

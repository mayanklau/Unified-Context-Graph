from typing import Annotated

from fastapi import APIRouter, Depends

from ucg.api.dependencies import get_graph_repository
from ucg.graph.repository import GraphRepository
from ucg.semantic_layer.models import SemanticQueryRequest, SemanticQueryResponse
from ucg.semantic_layer.service import SemanticLayerService

router = APIRouter()


@router.post("/query", response_model=SemanticQueryResponse)
def semantic_query(
    request: SemanticQueryRequest,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
) -> SemanticQueryResponse:
    return SemanticLayerService(repository).query(request)

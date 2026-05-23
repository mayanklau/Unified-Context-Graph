from typing import Annotated

from fastapi import APIRouter, Depends

from ucg.api.dependencies import get_graph_repository
from ucg.graph.repository import GraphRepository
from ucg.ingestion.models import IngestionEvent, IngestionResult
from ucg.ingestion.service import IngestionService

router = APIRouter()


@router.post("/events", response_model=IngestionResult)
def ingest_event(
    event: IngestionEvent,
    repository: Annotated[GraphRepository, Depends(get_graph_repository)],
) -> IngestionResult:
    return IngestionService(repository).ingest(event)

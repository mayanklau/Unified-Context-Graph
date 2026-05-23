from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ucg.graph.ontology import EdgeType, NodeType


class EntityRef(BaseModel):
    id: str
    type: NodeType
    name: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class IngestionEvent(BaseModel):
    source: str
    event_type: str
    actor: EntityRef
    object: EntityRef
    relationship: EdgeType
    tenant_id: str = "default"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_record_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class IngestionResult(BaseModel):
    node_ids: list[str]
    edge_id: str
    tenant_id: str

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field

from ucg.graph.ontology import EdgeType, NodeType


class Provenance(BaseModel):
    source: str
    source_record_id: str | None = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GraphNode(BaseModel):
    id: str
    type: NodeType
    name: str
    tenant_id: str = "default"
    attributes: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GraphEdge(BaseModel):
    id: str
    type: EdgeType
    source_id: str
    target_id: str
    tenant_id: str = "default"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def deterministic_id(
        cls,
        tenant_id: str,
        edge_type: EdgeType,
        source_id: str,
        target_id: str,
        source: str,
    ) -> str:
        value = f"{tenant_id}:{edge_type}:{source_id}:{target_id}:{source}"
        return f"edge:{uuid5(NAMESPACE_URL, value)}"


class GraphContext(BaseModel):
    root_id: str
    depth: int
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class GraphPath(BaseModel):
    source_id: str
    target_id: str
    node_ids: list[str]
    edge_ids: list[str]
    depth: int

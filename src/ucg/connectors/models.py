from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ConnectorStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


class ConnectorRegistration(BaseModel):
    id: str
    name: str
    source_type: str
    owner: str
    tenant_id: str = "default"
    version: str = "0.1.0"
    status: ConnectorStatus = ConnectorStatus.ACTIVE
    supported_node_types: list[str] = Field(default_factory=list)
    supported_edge_types: list[str] = Field(default_factory=list)
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ConnectorHealth(BaseModel):
    connector_id: str
    status: ConnectorStatus
    freshness_seconds: int
    coverage: dict[str, int] = Field(default_factory=dict)

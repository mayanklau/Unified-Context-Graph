from enum import StrEnum

from pydantic import BaseModel, Field


class IncidentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgenticSocFinding(BaseModel):
    id: str
    severity: IncidentSeverity
    summary: str
    affected_node_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

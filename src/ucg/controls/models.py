from enum import StrEnum

from pydantic import BaseModel, Field


class ControlStatus(StrEnum):
    UNKNOWN = "unknown"
    EFFECTIVE = "effective"
    PARTIAL = "partial"
    INEFFECTIVE = "ineffective"


class ControlFrameworkMapping(BaseModel):
    control_id: str
    framework: str
    requirement: str
    tenant_id: str = "default"
    evidence_node_ids: list[str] = Field(default_factory=list)
    status: ControlStatus = ControlStatus.UNKNOWN


class ControlAssessment(BaseModel):
    control_id: str
    status: ControlStatus
    rationale: list[str]
    evidence_node_ids: list[str] = Field(default_factory=list)

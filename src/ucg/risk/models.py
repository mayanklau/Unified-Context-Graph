from enum import StrEnum

from pydantic import BaseModel, Field


class RiskTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskScoreRequest(BaseModel):
    target_id: str
    tenant_id: str = "default"
    severity: float = Field(default=0.5, ge=0.0, le=1.0)
    exploitability: float = Field(default=0.5, ge=0.0, le=1.0)
    exposure: float = Field(default=0.5, ge=0.0, le=1.0)
    business_criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    data_sensitivity: float = Field(default=0.5, ge=0.0, le=1.0)
    control_strength: float = Field(default=0.5, ge=0.0, le=1.0)
    threat_activity: float = Field(default=0.5, ge=0.0, le=1.0)


class RiskScoreResponse(BaseModel):
    target_id: str
    score: float
    tier: RiskTier
    rationale: list[str]
    evidence_node_ids: list[str]

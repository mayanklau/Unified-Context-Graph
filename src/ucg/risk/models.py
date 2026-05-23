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


class RiskScenarioRequest(BaseModel):
    scenario_id: str
    name: str
    target_ids: list[str]
    tenant_id: str = "default"
    likelihood: float = Field(default=0.5, ge=0.0, le=1.0)
    impact: float = Field(default=0.5, ge=0.0, le=1.0)
    control_strength: float = Field(default=0.5, ge=0.0, le=1.0)
    annualized_loss_exposure: float | None = Field(default=None, ge=0.0)


class RiskScenarioResponse(BaseModel):
    scenario_id: str
    name: str
    score: float
    tier: RiskTier
    annualized_loss_exposure: float | None
    rationale: list[str]
    evidence_node_ids: list[str]

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"


class PolicyEvaluationRequest(BaseModel):
    actor_id: str
    action: str
    target_id: str
    tenant_id: str = "default"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    data_classification: str = "internal"
    attributes: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    outcome: PolicyOutcome
    reasons: list[str]
    required_controls: list[str] = Field(default_factory=list)
    evidence_node_ids: list[str] = Field(default_factory=list)

from pydantic import BaseModel, Field

from ucg.policy.models import PolicyDecision


class AgentActionEvaluationRequest(BaseModel):
    agent_id: str
    delegated_by: str | None = None
    action: str
    target_id: str
    tenant_id: str = "default"
    data_classification: str = "internal"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    tool_name: str | None = None
    purpose: str | None = None


class AgentActionEvaluation(BaseModel):
    agent_id: str
    target_id: str
    policy_decision: PolicyDecision
    trace: list[str]
    required_approvals: list[str] = Field(default_factory=list)

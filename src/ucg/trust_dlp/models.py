from enum import StrEnum

from pydantic import BaseModel, Field


class DLPDecision(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REVIEW = "review"
    ESCALATE = "escalate"


class DataMovementSurface(StrEnum):
    PROMPT = "prompt"
    RESPONSE = "response"
    TOOL_CALL = "tool_call"
    FILE = "file"
    NETWORK = "network"
    SAAS = "saas"
    ENDPOINT = "endpoint"


class TrustDLPPolicy(BaseModel):
    id: str
    name: str
    sensitive_categories: list[str] = Field(default_factory=list)
    allowed_purposes: list[str] = Field(default_factory=list)
    blocked_destinations: list[str] = Field(default_factory=list)
    required_controls: list[str] = Field(default_factory=list)


class DataMovementSignal(BaseModel):
    id: str
    actor_id: str
    source_id: str
    destination: str
    surface: DataMovementSurface
    data_categories: list[str] = Field(default_factory=list)
    purpose: str | None = None
    policy_ids: list[str] = Field(default_factory=list)
    evidence_node_ids: list[str] = Field(default_factory=list)
    recommended_decision: DLPDecision = DLPDecision.REVIEW

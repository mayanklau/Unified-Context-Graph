from enum import StrEnum

from pydantic import BaseModel, Field


class FirewallSurface(StrEnum):
    PROMPT = "prompt"
    RESPONSE = "response"
    TOOL_CALL = "tool_call"


class FirewallDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REVIEW = "review"


class FirewallInspectionRequest(BaseModel):
    surface: FirewallSurface
    content: str
    actor_id: str | None = None
    tenant_id: str = "default"
    context_labels: list[str] = Field(default_factory=list)


class FirewallFinding(BaseModel):
    category: str
    severity: str
    reason: str


class FirewallInspectionResponse(BaseModel):
    decision: FirewallDecision
    findings: list[FirewallFinding]
    recommended_controls: list[str] = Field(default_factory=list)

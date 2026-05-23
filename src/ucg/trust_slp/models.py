from enum import StrEnum

from pydantic import BaseModel, Field


class TrustPosture(StrEnum):
    UNKNOWN = "unknown"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


class TrustSignal(BaseModel):
    id: str
    subject_id: str
    posture: TrustPosture
    evidence_node_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)

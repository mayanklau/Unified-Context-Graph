from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceKind(StrEnum):
    LOG = "log"
    TICKET = "ticket"
    PROMPT = "prompt"
    RESPONSE = "response"
    POLICY_DECISION = "policy_decision"
    APPROVAL = "approval"
    CONTROL_ATTESTATION = "control_attestation"
    ARTIFACT = "artifact"


class EvidenceRecord(BaseModel):
    id: str
    kind: EvidenceKind
    title: str
    source: str
    tenant_id: str = "default"
    subject_ids: list[str] = Field(default_factory=list)
    uri: str | None = None
    content_hash: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidencePackage(BaseModel):
    subject_id: str
    tenant_id: str
    evidence: list[EvidenceRecord]

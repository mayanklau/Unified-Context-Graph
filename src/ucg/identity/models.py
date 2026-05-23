from enum import StrEnum

from pydantic import BaseModel, Field


class IdentityKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    WORKLOAD = "workload"
    AGENT = "agent"
    MODEL = "model"
    API_KEY = "api_key"
    SESSION = "session"


class IdentityProfile(BaseModel):
    id: str
    kind: IdentityKind
    display_name: str
    delegated_authorities: list[str] = Field(default_factory=list)
    linked_identities: list[str] = Field(default_factory=list)

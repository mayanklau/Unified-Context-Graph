"""Request bodies. Responses are plain dictionaries produced by the services."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginBody(_Body):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class SubgraphBody(_Body):
    seeds: list[str] = Field(min_length=1, max_length=100)
    depth: int = Field(default=1, ge=0)
    direction: str = "both"
    edge_types: list[str] | None = None
    max_nodes: int | None = Field(default=None, ge=1)
    as_of: str | None = None


class PathBody(_Body):
    source_id: str
    target_id: str
    max_depth: int | None = Field(default=None, ge=1)
    edge_types: list[str] | None = None
    directed: bool = False
    as_of: str | None = None


class MatchBody(_Body):
    pattern: dict[str, Any]
    as_of: str | None = None


class MergeBody(_Body):
    survivor_id: str
    duplicate_id: str


class ResolveBody(_Body):
    node_id: str


class IdsBody(_Body):
    ids: list[str] = Field(min_length=1, max_length=5000)


class NoteBody(_Body):
    kind: str
    title: str
    body: str = ""
    entity_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    signature: list[str] = Field(default_factory=list)
    confidence: float | None = None
    supersedes: str | None = None
    ttl_days: int | None = None


class FeedbackBody(_Body):
    outcome: str


class SuggestBody(_Body):
    entity_ids: list[str] = Field(default_factory=list)
    signature: list[str] = Field(default_factory=list)
    text: str | None = Field(default=None, max_length=1000)
    kinds: list[str] | None = None
    limit: int = Field(default=5, ge=1, le=50)


class UserCreateBody(_Body):
    username: str
    password: str
    roles: list[str]


class UserUpdateBody(_Body):
    roles: list[str] | None = None
    disabled: bool | None = None
    password: str | None = None


class ApiKeyBody(_Body):
    name: str
    roles: list[str]
    kind: str = "service"
    node_types: list[str] | None = None
    expires_in_days: int | None = None


class WebhookBody(_Body):
    name: str
    url: str
    event_kinds: list[str] = Field(default_factory=list)
    entity_types: list[str] = Field(default_factory=list)
    from_now: bool = True


class WebhookStateBody(_Body):
    active: bool

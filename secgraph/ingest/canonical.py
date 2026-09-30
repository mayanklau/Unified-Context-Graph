"""The canonical ingest contract.

Every source — whatever its native format — is mapped to these records
before it touches the graph. A batch is a list of node records and edge
records from one named source.

Node record::

    {"type": "Asset",
     "identifiers": {"fqdn": "web-01.corp.example", "ip": ["10.0.0.5"]},
     "properties": {"os": "Ubuntu 22.04", "criticality": 4},
     "ref": "a1"}                      # optional handle for edges in the same batch

Edge record::

    {"type": "HAS_FINDING",
     "source": {"ref": "a1"},
     "target": {"type": "Finding", "identifiers": {"finding_key": "scan:123"}}}

An endpoint is given by ``ref`` (a node in this batch), ``id`` (a graph node
id) or ``type`` + ``identifiers`` (resolved through the identity spine; a stub
node is created if the entity has not been seen yet, so load order never
loses an edge).
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")


class NodeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=64)
    identifiers: dict[str, Any] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    name: str | None = Field(default=None, max_length=512)
    ref: str | None = Field(default=None, max_length=128)
    observed_at: Any | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    op: Literal["upsert", "delete"] = "upsert"


class EndpointRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref: str | None = Field(default=None, max_length=128)
    id: str | None = Field(default=None, max_length=32)
    type: str | None = Field(default=None, max_length=64)
    identifiers: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _one_way(self) -> EndpointRef:
        ways = [self.ref is not None, self.id is not None, self.type is not None or self.identifiers is not None]
        if sum(ways) != 1:
            raise ValueError("give exactly one of 'ref', 'id', or 'type' + 'identifiers'")
        if ways[2] and (not self.type or not self.identifiers):
            raise ValueError("'type' and 'identifiers' must be given together")
        return self


class EdgeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=64)
    source: EndpointRef
    target: EndpointRef
    key: str = Field(default="", max_length=128)
    properties: dict[str, Any] = Field(default_factory=dict)
    observed_at: Any | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    op: Literal["upsert", "delete"] = "upsert"


class IngestRequest(BaseModel):
    """Envelope. Records stay as raw dicts so one bad record is quarantined, not the whole batch."""

    model_config = ConfigDict(extra="forbid")

    source: str
    observed_at: Any | None = None
    nodes: list[Any] = Field(default_factory=list)
    edges: list[Any] = Field(default_factory=list)

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        value = value.strip().lower()
        if not SOURCE_RE.match(value):
            raise ValueError("source must be 1-64 characters of a-z, 0-9, '_', '.', ':' or '-'")
        return value

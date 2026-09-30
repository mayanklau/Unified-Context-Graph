"""Plain value objects returned by the store.

Reads return these instead of ORM rows so that a current node and a node as
it was at some past time have exactly the same shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class NodeRecord:
    id: str
    type: str
    name: str
    properties: dict[str, Any]
    stub: bool = False
    confidence: float = 1.0
    version: int = 1
    valid_from: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: dict[str, str] = field(default_factory=dict)
    deleted: bool = False
    merged_into: str | None = None
    identifiers: dict[str, list[str]] | None = None  # filled on request


@dataclass(slots=True)
class EdgeRecord:
    id: str  # lineage id: stable across versions of the relationship
    type: str
    source: str
    target: str
    key: str
    properties: dict[str, Any]
    confidence: float = 1.0
    version: int = 1
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: dict[str, str] = field(default_factory=dict)

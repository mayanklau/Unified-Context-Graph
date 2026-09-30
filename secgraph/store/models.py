"""Relational schema of the graph.

Design notes
------------
* Every table carries ``tenant_id``; every query filters on it.
* ``nodes`` holds the current state of each entity; ``node_versions`` holds
  every superseded state, so "what did the graph say at time T" is answerable.
* ``edges`` is versioned in place: a row is current while ``valid_to`` is
  NULL; a change closes the row and inserts its successor.
* ``node_aliases`` is the identity spine: every identifier any source has
  used for an entity, pointing at the one node that represents it.
* ``change_events`` and ``audit_log`` are sequenced per tenant; the sequence
  is allocated under a row lock on ``tenants`` so order equals commit order.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from secgraph.store.types import JSONType, UTCDateTime, utcnow

ID = String(32)
TENANT = String(64)
TYPE = String(64)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # Monotonic per-tenant sequences, advanced under a row lock.
    change_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    audit_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    audit_head: Mapped[str] = mapped_column(String(64), default="0" * 64)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, ForeignKey("tenants.id"), nullable=False)
    type: Mapped[str] = mapped_column(TYPE, nullable=False)
    name: Mapped[str] = mapped_column(String(512), default="")
    name_norm: Mapped[str] = mapped_column(String(512), default="")
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    prop_sources: Mapped[dict[str, str]] = mapped_column(JSONType, default=dict)
    sources: Mapped[dict[str, str]] = mapped_column(JSONType, default=dict)
    stub: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    version: Mapped[int] = mapped_column(Integer, default=1)
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    merged_into: Mapped[str | None] = mapped_column(ID, nullable=True)
    changed_by: Mapped[str] = mapped_column(String(128), default="")  # source of the current version
    name_rank: Mapped[int] = mapped_column(Integer, default=999)  # which name_from entry produced ``name``

    __table_args__ = (
        Index("ix_nodes_tenant_type_name", "tenant_id", "type", "name_norm"),
        Index("ix_nodes_tenant_name", "tenant_id", "name_norm"),
        Index("ix_nodes_tenant_type_last_seen", "tenant_id", "type", "last_seen"),
        Index("ix_nodes_tenant_updated", "tenant_id", "updated_at"),
        Index(
            "ix_nodes_properties_gin",
            "properties",
            postgresql_using="gin",
            postgresql_ops={"properties": "jsonb_path_ops"},
        ).ddl_if(dialect="postgresql"),
    )


class NodeVersion(Base):
    """A superseded state of a node, valid during ``[valid_from, valid_to)``."""

    __tablename__ = "node_versions"

    node_id: Mapped[str] = mapped_column(ID, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    type: Mapped[str] = mapped_column(TYPE, nullable=False)
    name: Mapped[str] = mapped_column(String(512), default="")
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    stub: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    valid_to: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    changed_by: Mapped[str] = mapped_column(String(128), default="")

    __table_args__ = (Index("ix_node_versions_tenant_valid_to", "tenant_id", "valid_to"),)


class NodeAlias(Base):
    """Identity spine: one row per identifier ever used for an entity."""

    __tablename__ = "node_aliases"

    tenant_id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    node_type: Mapped[str] = mapped_column(TYPE, primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), primary_key=True)
    node_id: Mapped[str] = mapped_column(ID, primary_key=True)
    weak: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    __table_args__ = (
        # A strong identifier belongs to exactly one entity.
        Index(
            "uq_node_aliases_strong",
            "tenant_id",
            "node_type",
            "kind",
            "value",
            unique=True,
            postgresql_where=text("weak = false"),
            sqlite_where=text("weak = 0"),
        ),
        Index("ix_node_aliases_node", "tenant_id", "node_id"),
        Index("ix_node_aliases_value", "tenant_id", "value"),
    )


class Edge(Base):
    __tablename__ = "edges"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, ForeignKey("tenants.id"), nullable=False)
    type: Mapped[str] = mapped_column(TYPE, nullable=False)
    src_id: Mapped[str] = mapped_column(ID, nullable=False)
    dst_id: Mapped[str] = mapped_column(ID, nullable=False)
    edge_key: Mapped[str] = mapped_column(String(128), default="")
    # Stable identity of the relationship across its versions.
    lineage_id: Mapped[str] = mapped_column(ID, nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    sources: Mapped[dict[str, str]] = mapped_column(JSONType, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    version: Mapped[int] = mapped_column(Integer, default=1)
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    valid_to: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    __table_args__ = (
        Index(
            "uq_edges_current",
            "tenant_id",
            "type",
            "src_id",
            "dst_id",
            "edge_key",
            unique=True,
            postgresql_where=text("valid_to IS NULL"),
            sqlite_where=text("valid_to IS NULL"),
        ),
        Index("ix_edges_tenant_src", "tenant_id", "src_id", "type"),
        Index("ix_edges_tenant_dst", "tenant_id", "dst_id", "type"),
        Index("ix_edges_tenant_type_last_seen", "tenant_id", "type", "last_seen"),
        Index("ix_edges_lineage", "tenant_id", "lineage_id"),
    )


class ResolutionConflict(Base):
    """A case where entity resolution refused to guess; shown to a human for merge or dismissal."""

    __tablename__ = "resolution_conflicts"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    node_type: Mapped[str] = mapped_column(TYPE, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    node_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="open")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    __table_args__ = (
        Index("uq_resolution_conflicts_fp", "tenant_id", "fingerprint", unique=True),
        Index("ix_resolution_conflicts_status", "tenant_id", "status"),
    )


class IngestBatch(Base):
    __tablename__ = "ingest_batches"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    mapping: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    ontology_version: Mapped[str] = mapped_column(String(32), default="")
    ontology_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    principal: Mapped[str] = mapped_column(String(128), default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_ingest_batches_tenant_started", "tenant_id", "started_at"),)


class QuarantinedRecord(Base):
    """A record that failed validation. Kept verbatim so it can be fixed and replayed."""

    __tablename__ = "quarantine"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    batch_id: Mapped[str | None] = mapped_column(ID, nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="")
    kind: Mapped[str] = mapped_column(String(16), default="node")  # node | edge | source_record
    record: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | replayed | discarded
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    __table_args__ = (
        Index("ix_quarantine_tenant_status", "tenant_id", "status", "created_at"),
        Index("ix_quarantine_batch", "tenant_id", "batch_id"),
    )


class ChangeEvent(Base):
    """Ordered change feed (transactional outbox) consumed by downstream products."""

    __tablename__ = "change_events"

    tenant_id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # node.created, edge.deleted, ...
    entity_type: Mapped[str] = mapped_column(TYPE, nullable=False)
    entity_id: Mapped[str] = mapped_column(ID, nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    batch_id: Mapped[str | None] = mapped_column(ID, nullable=True)

    __table_args__ = (Index("ix_change_events_ts", "tenant_id", "ts"),)


class AuditEntry(Base):
    """Hash-chained audit log: hash = SHA-256(prev_hash || canonical entry)."""

    __tablename__ = "audit_log"

    tenant_id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    request_id: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (Index("ix_audit_log_action", "tenant_id", "action", "ts"),)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), default="service")  # service | agent
    roles: Mapped[list[str]] = mapped_column(JSONType, default=list)
    node_types: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)  # None = all types
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    __table_args__ = (Index("ix_api_keys_tenant", "tenant_id"),)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, ForeignKey("tenants.id"), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    roles: Mapped[list[str]] = mapped_column(JSONType, default=list)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class MemoryNote(Base):
    """Shared agent/analyst memory: observations, decisions, lessons and playbooks tied to entities."""

    __tablename__ = "memory_notes"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    signature: Mapped[list[str]] = mapped_column(JSONType, default=list)
    author: Mapped[str] = mapped_column(String(128), default="")
    author_kind: Mapped[str] = mapped_column(String(16), default="user")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | archived
    uses: Mapped[int] = mapped_column(Integer, default=0)
    successes: Mapped[int] = mapped_column(Integer, default=0)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    token_count: Mapped[int] = mapped_column(Integer, default=0)
    supersedes: Mapped[str | None] = mapped_column(ID, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    __table_args__ = (Index("ix_memory_notes_tenant", "tenant_id", "status", "updated_at"),)


class MemoryLink(Base):
    __tablename__ = "memory_links"

    tenant_id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    note_id: Mapped[str] = mapped_column(ID, primary_key=True)
    node_id: Mapped[str] = mapped_column(ID, primary_key=True)

    __table_args__ = (Index("ix_memory_links_node", "tenant_id", "node_id"),)


class MemoryTerm(Base):
    """Inverted index over note text and signature features (portable lexical search)."""

    __tablename__ = "memory_terms"

    tenant_id: Mapped[str] = mapped_column(TENANT, primary_key=True)
    term: Mapped[str] = mapped_column(String(96), primary_key=True)
    note_id: Mapped[str] = mapped_column(ID, primary_key=True)
    tf: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (Index("ix_memory_terms_note", "tenant_id", "note_id"),)


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(TENANT, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    event_kinds: Mapped[list[str]] = mapped_column(JSONType, default=list)  # empty = all
    entity_types: Mapped[list[str]] = mapped_column(JSONType, default=list)  # empty = all
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    cursor: Mapped[int] = mapped_column(BigInteger, default=0)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_delivery_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    __table_args__ = (Index("ix_webhooks_tenant", "tenant_id"),)

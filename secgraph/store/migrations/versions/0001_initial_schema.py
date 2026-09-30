"""Initial schema: graph, identity spine, history, change feed, audit, access, memory, webhooks.

Revision ID: 0001
Revises:
Create Date: 2026-09-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# JSONB on PostgreSQL (indexable, containment queries); plain JSON on SQLite.
JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("detail", JSON, nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "seq"),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["tenant_id", "action", "ts"], unique=False)
    op.create_table(
        "change_events",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=32), nullable=False),
        sa.Column("data", JSON, nullable=False),
        sa.Column("batch_id", sa.String(length=32), nullable=True),
        sa.PrimaryKeyConstraint("tenant_id", "seq"),
    )
    op.create_index("ix_change_events_ts", "change_events", ["tenant_id", "ts"], unique=False)
    op.create_table(
        "ingest_batches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("mapping", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("counts", JSON, nullable=False),
        sa.Column("ontology_version", sa.String(length=32), nullable=False),
        sa.Column("ontology_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("principal", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ingest_batches_tenant_started", "ingest_batches", ["tenant_id", "started_at"], unique=False)
    op.create_table(
        "memory_links",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("note_id", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "note_id", "node_id"),
    )
    op.create_index("ix_memory_links_node", "memory_links", ["tenant_id", "node_id"], unique=False)
    op.create_table(
        "memory_notes",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("tags", JSON, nullable=False),
        sa.Column("signature", JSON, nullable=False),
        sa.Column("author", sa.String(length=128), nullable=False),
        sa.Column("author_kind", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False),
        sa.Column("successes", sa.Integer(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("token_count", sa.Integer(), nullable=False),
        sa.Column("supersedes", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_memory_notes_tenant", "memory_notes", ["tenant_id", "status", "updated_at"], unique=False)
    op.create_table(
        "memory_terms",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("term", sa.String(length=96), nullable=False),
        sa.Column("note_id", sa.String(length=32), nullable=False),
        sa.Column("tf", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "term", "note_id"),
    )
    op.create_index("ix_memory_terms_note", "memory_terms", ["tenant_id", "note_id"], unique=False)
    op.create_table(
        "node_aliases",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("node_type", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("weak", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "node_type", "kind", "value", "node_id"),
    )
    op.create_index("ix_node_aliases_node", "node_aliases", ["tenant_id", "node_id"], unique=False)
    op.create_index("ix_node_aliases_value", "node_aliases", ["tenant_id", "value"], unique=False)
    op.create_index(
        "uq_node_aliases_strong",
        "node_aliases",
        ["tenant_id", "node_type", "kind", "value"],
        unique=True,
        postgresql_where=sa.text("weak = false"),
        sqlite_where=sa.text("weak = 0"),
    )
    op.create_table(
        "node_versions",
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("properties", JSON, nullable=False),
        sa.Column("stub", sa.Boolean(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_by", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("node_id", "version"),
    )
    op.create_index("ix_node_versions_tenant_valid_to", "node_versions", ["tenant_id", "valid_to"], unique=False)
    op.create_table(
        "quarantine",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("batch_id", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("record", JSON, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_quarantine_batch", "quarantine", ["tenant_id", "batch_id"], unique=False)
    op.create_index("ix_quarantine_tenant_status", "quarantine", ["tenant_id", "status", "created_at"], unique=False)
    op.create_table(
        "resolution_conflicts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("node_type", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("node_ids", JSON, nullable=False),
        sa.Column("detail", JSON, nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_resolution_conflicts_status", "resolution_conflicts", ["tenant_id", "status"], unique=False)
    op.create_index("uq_resolution_conflicts_fp", "resolution_conflicts", ["tenant_id", "fingerprint"], unique=True)
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_seq", sa.BigInteger(), nullable=False),
        sa.Column("audit_seq", sa.BigInteger(), nullable=False),
        sa.Column("audit_head", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "webhooks",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("event_kinds", JSON, nullable=False),
        sa.Column("entity_types", JSON, nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("cursor", sa.BigInteger(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhooks_tenant", "webhooks", ["tenant_id"], unique=False)
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("roles", JSON, nullable=False),
        sa.Column("node_types", JSON, nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("prefix"),
    )
    op.create_index("ix_api_keys_tenant", "api_keys", ["tenant_id"], unique=False)
    op.create_table(
        "edges",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("src_id", sa.String(length=32), nullable=False),
        sa.Column("dst_id", sa.String(length=32), nullable=False),
        sa.Column("edge_key", sa.String(length=128), nullable=False),
        sa.Column("lineage_id", sa.String(length=32), nullable=False),
        sa.Column("properties", JSON, nullable=False),
        sa.Column("sources", JSON, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_edges_lineage", "edges", ["tenant_id", "lineage_id"], unique=False)
    op.create_index("ix_edges_tenant_dst", "edges", ["tenant_id", "dst_id", "type"], unique=False)
    op.create_index("ix_edges_tenant_src", "edges", ["tenant_id", "src_id", "type"], unique=False)
    op.create_index("ix_edges_tenant_type_last_seen", "edges", ["tenant_id", "type", "last_seen"], unique=False)
    op.create_index(
        "uq_edges_current",
        "edges",
        ["tenant_id", "type", "src_id", "dst_id", "edge_key"],
        unique=True,
        postgresql_where=sa.text("valid_to IS NULL"),
        sqlite_where=sa.text("valid_to IS NULL"),
    )
    op.create_table(
        "nodes",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("name_norm", sa.String(length=512), nullable=False),
        sa.Column("properties", JSON, nullable=False),
        sa.Column("prop_sources", JSON, nullable=False),
        sa.Column("sources", JSON, nullable=False),
        sa.Column("stub", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("merged_into", sa.String(length=32), nullable=True),
        sa.Column("changed_by", sa.String(length=128), nullable=False),
        sa.Column("name_rank", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    if _is_postgresql():
        op.create_index(
            "ix_nodes_properties_gin",
            "nodes",
            ["properties"],
            unique=False,
            postgresql_using="gin",
            postgresql_ops={"properties": "jsonb_path_ops"},
        )
    op.create_index("ix_nodes_tenant_name", "nodes", ["tenant_id", "name_norm"], unique=False)
    op.create_index("ix_nodes_tenant_type_last_seen", "nodes", ["tenant_id", "type", "last_seen"], unique=False)
    op.create_index("ix_nodes_tenant_type_name", "nodes", ["tenant_id", "type", "name_norm"], unique=False)
    op.create_index("ix_nodes_tenant_updated", "nodes", ["tenant_id", "updated_at"], unique=False)
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("roles", JSON, nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_index("ix_nodes_tenant_updated", table_name="nodes")
    op.drop_index("ix_nodes_tenant_type_name", table_name="nodes")
    op.drop_index("ix_nodes_tenant_type_last_seen", table_name="nodes")
    op.drop_index("ix_nodes_tenant_name", table_name="nodes")
    if _is_postgresql():
        op.drop_index("ix_nodes_properties_gin", table_name="nodes")
    op.drop_table("nodes")
    op.drop_index(
        "uq_edges_current",
        table_name="edges",
        postgresql_where=sa.text("valid_to IS NULL"),
        sqlite_where=sa.text("valid_to IS NULL"),
    )
    op.drop_index("ix_edges_tenant_type_last_seen", table_name="edges")
    op.drop_index("ix_edges_tenant_src", table_name="edges")
    op.drop_index("ix_edges_tenant_dst", table_name="edges")
    op.drop_index("ix_edges_lineage", table_name="edges")
    op.drop_table("edges")
    op.drop_index("ix_api_keys_tenant", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_webhooks_tenant", table_name="webhooks")
    op.drop_table("webhooks")
    op.drop_table("tenants")
    op.drop_index("uq_resolution_conflicts_fp", table_name="resolution_conflicts")
    op.drop_index("ix_resolution_conflicts_status", table_name="resolution_conflicts")
    op.drop_table("resolution_conflicts")
    op.drop_index("ix_quarantine_tenant_status", table_name="quarantine")
    op.drop_index("ix_quarantine_batch", table_name="quarantine")
    op.drop_table("quarantine")
    op.drop_index("ix_node_versions_tenant_valid_to", table_name="node_versions")
    op.drop_table("node_versions")
    op.drop_index(
        "uq_node_aliases_strong",
        table_name="node_aliases",
        postgresql_where=sa.text("weak = false"),
        sqlite_where=sa.text("weak = 0"),
    )
    op.drop_index("ix_node_aliases_value", table_name="node_aliases")
    op.drop_index("ix_node_aliases_node", table_name="node_aliases")
    op.drop_table("node_aliases")
    op.drop_index("ix_memory_terms_note", table_name="memory_terms")
    op.drop_table("memory_terms")
    op.drop_index("ix_memory_notes_tenant", table_name="memory_notes")
    op.drop_table("memory_notes")
    op.drop_index("ix_memory_links_node", table_name="memory_links")
    op.drop_table("memory_links")
    op.drop_index("ix_ingest_batches_tenant_started", table_name="ingest_batches")
    op.drop_table("ingest_batches")
    op.drop_index("ix_change_events_ts", table_name="change_events")
    op.drop_table("change_events")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_table("audit_log")

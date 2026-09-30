"""Schema migrations (Alembic), callable from the CLI, the API start-up and tests."""

from __future__ import annotations

from typing import Any

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, pool

from secgraph.config import Settings, get_settings
from secgraph.store.models import Base


def alembic_config(settings: Settings | None = None) -> Config:
    settings = settings or get_settings()
    config = Config()
    config.set_main_option("script_location", "secgraph.store:migrations")
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    return config


def upgrade(settings: Settings | None = None, revision: str = "head") -> None:
    command.upgrade(alembic_config(settings), revision)


def downgrade(settings: Settings | None = None, revision: str = "base") -> None:
    command.downgrade(alembic_config(settings), revision)


def status(settings: Settings | None = None) -> dict[str, Any]:
    """Current and latest revision, and whether the database is up to date."""
    settings = settings or get_settings()
    head = ScriptDirectory.from_config(alembic_config(settings)).get_current_head()
    engine = create_engine(settings.database_url, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            current = MigrationContext.configure(connection).get_current_revision()
    finally:
        engine.dispose()
    return {"current": current, "head": head, "up_to_date": current == head}


def schema_drift(settings: Settings | None = None) -> list[Any]:
    """Differences between the migrated database and the models (empty when they agree)."""
    settings = settings or get_settings()
    engine = create_engine(settings.database_url, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            differences = list(compare_metadata(context, Base.metadata))
            if connection.dialect.name != "postgresql":
                # PostgreSQL-only indexes (GIN on JSONB) are intentionally absent elsewhere.
                differences = [
                    d
                    for d in differences
                    if not (d[0] == "add_index" and d[1].dialect_options["postgresql"].get("using"))
                ]
            return differences
    finally:
        engine.dispose()

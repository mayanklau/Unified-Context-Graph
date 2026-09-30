"""Migrations build exactly the schema the models describe, on both backends."""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text

from secgraph.store import migrate
from secgraph.store.models import Base
from tests.conftest import TEST_DB_URL, make_settings


def _check(settings):
    assert migrate.status(settings) == {"current": None, "head": "0001", "up_to_date": False}
    migrate.upgrade(settings)
    assert migrate.status(settings)["up_to_date"] is True
    drift = migrate.schema_drift(settings)
    assert drift == [], f"models and migrations disagree: {drift}"
    engine = create_engine(settings.database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert set(Base.metadata.tables) <= tables
        indexes = {i["name"] for i in inspect(engine).get_indexes("edges")}
        assert "uq_edges_current" in indexes
    finally:
        engine.dispose()
    migrate.upgrade(settings)  # idempotent
    migrate.downgrade(settings)
    engine = create_engine(settings.database_url)
    try:
        assert set(inspect(engine).get_table_names()) - {"alembic_version"} == set()
    finally:
        engine.dispose()


def test_migrations_on_sqlite(tmp_path):
    _check(make_settings(f"sqlite:///{tmp_path / 'migrate.db'}"))


@pytest.mark.postgres
def test_migrations_on_postgresql():
    # A private schema keeps this test independent of the tables the rest of the suite uses.
    schema = "mig_" + uuid.uuid4().hex[:10]
    admin = create_engine(TEST_DB_URL, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        separator = "&" if "?" in TEST_DB_URL else "?"
        url = f"{TEST_DB_URL}{separator}options=-csearch_path%3D{schema}"
        _check(make_settings(url))
        engine = create_engine(url)
        try:
            migrate.upgrade(make_settings(url))
            indexes = {i["name"] for i in inspect(engine).get_indexes("nodes", schema=schema)}
            assert "ix_nodes_properties_gin" in indexes
        finally:
            engine.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
    assert os.environ.get("SECGRAPH_TEST_DATABASE_URL")

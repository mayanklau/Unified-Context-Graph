"""Shared fixtures.

The suite runs against SQLite by default. Set ``SECGRAPH_TEST_DATABASE_URL`` to a
PostgreSQL URL to run the same tests against PostgreSQL (CI does both). Tests are
isolated by tenant: every test gets a fresh tenant id, which also exercises the
tenant boundary on every query.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

from secgraph.config import Settings, set_settings
from secgraph.ingest.canonical import IngestRequest
from secgraph.ingest.service import IngestResult, IngestService
from secgraph.ontology import Ontology, load_ontology
from secgraph.store.db import Database

TEST_DB_URL = os.environ.get("SECGRAPH_TEST_DATABASE_URL", "")


def make_settings(database_url: str, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "database_url": database_url,
        "environment": "development",
        "jwt_secret": "test-secret-test-secret-test-secret-0123456789",
        "log_json": False,
        "log_level": "WARNING",
        "rate_limit_per_minute": 100_000,
        "rate_limit_burst": 100_000,
        "analytics_mc_samples": 4000,
        "analytics_cache_ttl_seconds": 0,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def database_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    if TEST_DB_URL:
        return TEST_DB_URL
    return f"sqlite:///{tmp_path_factory.mktemp('db') / 'secgraph-test.db'}"


@pytest.fixture(scope="session")
def settings(database_url: str) -> Settings:
    return make_settings(database_url)


@pytest.fixture(scope="session")
def db(settings: Settings) -> Iterator[Database]:
    database = Database(settings)
    database.drop_all()
    database.create_all()
    set_settings(settings)
    yield database
    database.dispose()
    set_settings(None)


@pytest.fixture(scope="session")
def ontology() -> Ontology:
    return load_ontology()


@pytest.fixture()
def tenant() -> str:
    return "t-" + uuid.uuid4().hex[:12]


@pytest.fixture()
def ingest_service(db: Database, ontology: Ontology, settings: Settings) -> IngestService:
    return IngestService(db, ontology, settings)


class Loader:
    """Small helper: ``load(nodes=[...], edges=[...])`` ingests one batch for the test's tenant."""

    def __init__(self, service: IngestService, tenant: str):
        self.service = service
        self.tenant = tenant

    def __call__(
        self,
        nodes: list[dict] | None = None,
        edges: list[dict] | None = None,
        *,
        source: str = "test",
        observed_at: object | None = None,
    ) -> IngestResult:
        request = IngestRequest(source=source, nodes=nodes or [], edges=edges or [], observed_at=observed_at)
        return self.service.ingest(self.tenant, "user:test", request)


@pytest.fixture()
def load(ingest_service: IngestService, tenant: str) -> Loader:
    return Loader(ingest_service, tenant)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if TEST_DB_URL.startswith("postgresql"):
        return
    skip = pytest.mark.skip(reason="set SECGRAPH_TEST_DATABASE_URL to a PostgreSQL URL to run")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip)

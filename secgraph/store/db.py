"""Engine and session management."""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from secgraph.config import Settings
from secgraph.errors import RetryableWrite
from secgraph.observability import get_logger
from secgraph.store.models import Base, Tenant
from secgraph.store.types import utcnow

log = get_logger(__name__)
T = TypeVar("T")

# PostgreSQL SQLSTATEs that mean "try the transaction again".
_RETRYABLE_SQLSTATES = {"40001", "40P01", "55P03"}  # serialization_failure, deadlock_detected, lock_not_available


class Database:
    """One engine + session factory. Create once per process."""

    def __init__(self, settings: Settings):
        self.settings = settings
        url = settings.database_url
        self.is_sqlite = url.startswith("sqlite")
        kwargs: dict[str, Any] = {"future": True}
        if self.is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if ":memory:" in url or url in ("sqlite://", "sqlite:///"):
                kwargs["poolclass"] = StaticPool
        else:
            kwargs.update(
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_pre_ping=True,
                pool_recycle=1800,
            )
            if url.startswith("postgresql"):
                kwargs["connect_args"] = {
                    "options": f"-c statement_timeout={int(settings.db_statement_timeout_ms)} -c timezone=UTC",
                    "application_name": settings.app_name,
                }
        self.engine: Engine = create_engine(url, **kwargs)
        if self.is_sqlite:
            _configure_sqlite(self.engine)
        self._factory = sessionmaker(self.engine, expire_on_commit=False, future=True)

    @property
    def dialect(self) -> str:
        return self.engine.dialect.name

    def session(self) -> Session:
        return self._factory()

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """One unit of work: commit on success, roll back on any error."""
        session = self._factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    @contextmanager
    def snapshot(self) -> Iterator[Session]:
        """Read-only unit of work on one consistent snapshot (REPEATABLE READ on PostgreSQL).

        Used by analytics, which read the graph in many statements and must not
        see half of a concurrent ingest batch.
        """
        session = self._factory()
        try:
            if not self.is_sqlite:
                session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            yield session
        finally:
            session.expunge_all()  # rows read here stay usable after the snapshot ends
            session.rollback()
            session.close()

    def run(self, work: Callable[[Session], T], *, attempts: int = 8) -> T:
        """Run ``work`` in a transaction, retrying when a concurrent writer wins a race."""
        delay = 0.02
        for attempt in range(1, attempts + 1):
            try:
                with self.transaction() as session:
                    return work(session)
            except RetryableWrite:
                if attempt == attempts:
                    raise
            except (OperationalError, IntegrityError) as exc:
                if attempt == attempts or not is_retryable(exc):
                    raise
                log.warning("retrying transaction", attempt=attempt, error=str(exc.orig)[:200])
            time.sleep(delay + random.uniform(0, delay))  # noqa: S311 - jitter, not security
            delay = min(delay * 2, 1.0)
        raise RetryableWrite("transaction could not be completed")  # pragma: no cover

    def create_all(self) -> None:
        """Create the schema directly (tests and throwaway development databases)."""
        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        Base.metadata.drop_all(self.engine)

    def refresh_statistics(self, tables: tuple[str, ...] = ("nodes", "node_aliases", "edges")) -> bool:
        """Ask PostgreSQL to re-sample the hot tables. A no-op elsewhere.

        The planner chooses indexes from table statistics. When a tenant's data appears or grows
        quickly — a first load — the statistics still say that tenant has no rows, and lookups
        that should touch a handful of rows scan the tenant's whole table instead. Autovacuum
        catches up eventually; a bulk load cannot wait for it.
        """
        if self.dialect != "postgresql":
            return False
        try:
            with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                for table in tables:
                    if table not in Base.metadata.tables:
                        raise ValueError(f"unknown table {table!r}")
                    conn.execute(text(f"ANALYZE {table}"))  # noqa: S608 - names checked against the schema above
            return True
        except Exception:
            log.warning("could not refresh table statistics", exc_info=True)
            return False

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def dispose(self) -> None:
        self.engine.dispose()


def is_retryable(exc: DBAPIError) -> bool:
    orig = exc.orig
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    if sqlstate in _RETRYABLE_SQLSTATES:
        return True
    message = str(orig).lower()
    if "database is locked" in message or "database table is locked" in message:
        return True
    if isinstance(exc, IntegrityError):
        # A unique violation on the identity spine or the current-edge index means a
        # concurrent writer created the same entity; re-resolving will find it.
        return sqlstate == "23505" or "unique constraint failed" in message
    return False


def _configure_sqlite(engine: Engine) -> None:
    """SQLite is the development backend. Transactions start with BEGIN IMMEDIATE so
    a unit of work never fails halfway on a stale snapshot; writers simply queue."""

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn: Any, _record: Any) -> None:
        dbapi_conn.isolation_level = None  # SQLAlchemy emits BEGIN itself (see below)
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _begin(conn: Any) -> None:
        conn.exec_driver_sql("BEGIN IMMEDIATE")


def ensure_tenant(session: Session, tenant_id: str, name: str = "") -> Tenant:
    """Return the tenant row, creating it if needed. Safe when several writers create it at once."""
    tenant = session.get(Tenant, tenant_id)
    if tenant is not None:
        return tenant
    values = {
        "id": tenant_id,
        "name": name or tenant_id,
        "created_at": utcnow(),
        "change_seq": 0,
        "audit_seq": 0,
        "audit_head": "0" * 64,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        session.execute(pg_insert(Tenant).values(**values).on_conflict_do_nothing(index_elements=["id"]))
    else:
        session.execute(sqlite_insert(Tenant).values(**values).on_conflict_do_nothing(index_elements=["id"]))
    tenant = session.get(Tenant, tenant_id)
    if tenant is None:  # pragma: no cover - the row exists once the statement above returns
        raise RetryableWrite("tenant creation raced")
    return tenant


def lock_tenant(session: Session, tenant_id: str) -> Tenant:
    """Take the per-tenant sequence lock until the transaction ends.

    Sequence numbers for the change feed and the audit chain are allocated
    while this lock is held, and the lock is released by commit, so sequence
    order equals commit order and a reader can never skip an event.
    """
    # FOR NO KEY UPDATE: every node and edge insert holds a key-share lock on its tenant row
    # (foreign key). A plain FOR UPDATE would conflict with those and deadlock concurrent writers.
    stmt = select(Tenant).where(Tenant.id == tenant_id).with_for_update(key_share=True)
    tenant = session.execute(stmt.execution_options(populate_existing=True)).scalar_one_or_none()
    if tenant is None:
        ensure_tenant(session, tenant_id)
        tenant = session.execute(stmt.execution_options(populate_existing=True)).scalar_one()
    return tenant

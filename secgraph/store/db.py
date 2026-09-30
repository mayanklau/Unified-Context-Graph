"""Engine and session management."""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from secgraph.config import Settings
from secgraph.errors import RetryableWrite
from secgraph.observability import get_logger
from secgraph.store.models import Base, Tenant

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

    def run(self, work: Callable[[Session], T], *, attempts: int = 5) -> T:
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
    tenant = session.get(Tenant, tenant_id)
    if tenant is None:
        tenant = Tenant(id=tenant_id, name=name or tenant_id)
        session.add(tenant)
        try:
            with session.begin_nested():
                session.flush()
        except IntegrityError:
            session.expunge(tenant)
            tenant = session.get(Tenant, tenant_id)
            if tenant is None:  # pragma: no cover - only under extreme races
                raise RetryableWrite("tenant creation raced") from None
    return tenant


def lock_tenant(session: Session, tenant_id: str) -> Tenant:
    """Take the per-tenant sequence lock until the transaction ends.

    Sequence numbers for the change feed and the audit chain are allocated
    while this lock is held, and the lock is released by commit, so sequence
    order equals commit order and a reader can never skip an event.
    """
    stmt = select(Tenant).where(Tenant.id == tenant_id).with_for_update()
    tenant = session.execute(stmt.execution_options(populate_existing=True)).scalar_one_or_none()
    if tenant is None:
        ensure_tenant(session, tenant_id)
        tenant = session.execute(stmt.execution_options(populate_existing=True)).scalar_one()
    return tenant

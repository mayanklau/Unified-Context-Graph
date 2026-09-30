"""Typed configuration.

Every setting comes from an environment variable prefixed ``SECGRAPH_`` or a
``.env`` file. Nothing is read from the network, so the service starts in an
air-gapped environment with no outbound connectivity.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from secgraph.errors import ConfigurationError

_INSECURE_SECRETS = {"", "change-me-in-production", "replace-with-32-plus-random-bytes"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECGRAPH_", env_file=".env", extra="ignore")

    # --- service
    app_name: str = "security-graph"
    environment: str = "development"  # development | staging | production
    log_level: str = "INFO"
    log_json: bool = True
    docs_enabled: bool = True  # OpenAPI UI at /docs (uses local assets only when vendored; see OPERATIONS.md)
    cors_origins: str = ""  # comma-separated; empty = same-origin only

    # --- persistence
    database_url: str = "sqlite:///./secgraph.db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_statement_timeout_ms: int = 30_000  # PostgreSQL only
    auto_migrate: bool = False  # run Alembic migrations on start (single-replica / dev convenience)

    # --- ontology
    ontology_file: str | None = None  # path to override the packaged core ontology
    source_priority: str = ""  # comma-separated source names, highest priority first

    # --- tenancy
    default_tenant: str = "default"

    # --- auth
    jwt_secret: str = "change-me-in-production"
    jwt_issuer: str = "secgraph"
    jwt_ttl_seconds: int = 3600
    # Externally issued tokens (on-prem IdP such as Keycloak / ADFS): PEM public key, RS256/ES256.
    oidc_public_key_file: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_roles_claim: str = "roles"
    oidc_tenant_claim: str = "tenant"
    bootstrap_admin_password: str | None = None  # development only; refused in production
    login_max_failures: int = 5
    login_lockout_seconds: int = 900

    # --- governance
    rate_limit_per_minute: int = 600
    rate_limit_burst: int = 120
    guardrail_webhook_url: str | None = None  # AgentPEP / LLM Firewall / Thoth
    guardrail_fail_closed: bool = True
    guardrail_timeout_s: float = 5.0

    # --- ingestion limits
    ingest_max_records: int = 50_000  # per request
    ingest_chunk_size: int = 500
    ingest_max_body_bytes: int = 64 * 1024 * 1024
    max_property_bytes: int = 64 * 1024  # serialized size of one record's properties

    # --- query limits
    query_max_depth: int = 6
    query_max_nodes: int = 5_000
    query_default_limit: int = 100
    query_max_limit: int = 1_000

    # --- analytics limits
    analytics_max_nodes: int = 250_000
    analytics_max_edges: int = 2_000_000
    analytics_mc_samples: int = 2_000
    analytics_mc_budget: int = 40_000_000  # samples x edges held in memory per chunk
    analytics_cache_ttl_seconds: int = 300
    analytics_seed: int = 20260930

    # --- events / webhooks
    webhook_timeout_s: float = 10.0
    webhook_max_attempts: int = 8
    webhook_allowed_hosts: str = ""  # comma-separated hostnames / CIDRs; empty = any non-blocked host
    webhook_allow_private: bool = True  # on-prem targets are private by nature; link-local is always blocked
    change_retention_days: int = 30
    history_retention_days: int = 0  # 0 = keep node/edge history forever

    # --- agent memory
    memory_max_body_chars: int = 20_000
    context_default_budget_tokens: int = 2_000
    context_max_budget_tokens: int = 16_000

    # --- worker
    worker_interval_seconds: float = 5.0
    maintenance_interval_seconds: float = 3600.0

    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def source_priority_list(self) -> list[str]:
        return [s.strip() for s in self.source_priority.split(",") if s.strip()]

    def cors_origin_list(self) -> list[str]:
        return [s.strip() for s in self.cors_origins.split(",") if s.strip()]

    def webhook_allowed_host_list(self) -> list[str]:
        return [s.strip() for s in self.webhook_allowed_hosts.split(",") if s.strip()]

    def validate_for_environment(self) -> None:
        """Refuse to start in production with development defaults."""
        if not self.is_production():
            return
        problems: list[str] = []
        if self.jwt_secret in _INSECURE_SECRETS or len(self.jwt_secret) < 32:
            problems.append("SECGRAPH_JWT_SECRET must be set to 32+ random characters")
        if self.bootstrap_admin_password:
            problems.append("SECGRAPH_BOOTSTRAP_ADMIN_PASSWORD is not allowed in production")
        if self.database_url.startswith("sqlite"):
            problems.append("SECGRAPH_DATABASE_URL must point at PostgreSQL in production")
        if "*" in self.cors_origin_list():
            problems.append("SECGRAPH_CORS_ORIGINS must not contain '*' in production")
        if problems:
            raise ConfigurationError("unsafe production configuration: " + "; ".join(problems))


class _Holder:
    override: Settings | None = None


@lru_cache(maxsize=1)
def _cached() -> Settings:
    return Settings()


def get_settings() -> Settings:
    return _Holder.override or _cached()


def set_settings(settings: Settings | None) -> None:
    """Install explicit settings (tests, embedded use) or clear them with ``None``."""
    _Holder.override = settings
    _cached.cache_clear()


__all__ = ["Settings", "get_settings", "set_settings", "Field"]

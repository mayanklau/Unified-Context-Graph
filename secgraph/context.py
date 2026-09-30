"""Application context: every service, wired once.

The API, the MCP server, the CLI and the worker all build the same
``AppContext`` so behaviour is identical whichever door a request comes in by.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secgraph.agents.context import ContextService
from secgraph.agents.mcp import McpServer
from secgraph.agents.memory import MemoryService
from secgraph.analytics.service import AnalyticsService
from secgraph.config import Settings, get_settings
from secgraph.events.webhooks import WebhookService
from secgraph.governance.auth import AuthService
from secgraph.governance.guardrail import Guardrail
from secgraph.governance.ratelimit import RateLimiter
from secgraph.ingest.curation import CurationService
from secgraph.ingest.mapping import MappingRegistry
from secgraph.ingest.service import IngestService
from secgraph.ontology import Ontology, get_ontology
from secgraph.query.service import QueryService
from secgraph.store.db import Database


@dataclass
class AppContext:
    settings: Settings
    db: Database
    ontology: Ontology
    auth: AuthService
    limiter: RateLimiter
    login_limiter: RateLimiter
    guardrail: Guardrail
    ingest: IngestService
    curation: CurationService
    mappings: MappingRegistry
    query: QueryService
    analytics: AnalyticsService
    memory: MemoryService
    context: ContextService
    webhooks: WebhookService
    mcp: McpServer = field(init=False)

    def __post_init__(self) -> None:
        self.mcp = McpServer(self)

    def close(self) -> None:
        self.db.dispose()


def build_context(settings: Settings | None = None, *, db: Database | None = None) -> AppContext:
    settings = settings or get_settings()
    settings.validate_for_environment()
    ontology = get_ontology(settings.ontology_file)
    database = db or Database(settings)
    guardrail = Guardrail(settings)
    ingest = IngestService(database, ontology, settings)
    analytics = AnalyticsService(database, ontology, settings)
    memory = MemoryService(database, ontology, settings, guardrail)
    return AppContext(
        settings=settings,
        db=database,
        ontology=ontology,
        auth=AuthService(database, settings),
        limiter=RateLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst),
        login_limiter=RateLimiter(10, 10),
        guardrail=guardrail,
        ingest=ingest,
        curation=CurationService(database, ontology, settings, ingest),
        mappings=MappingRegistry(ontology, settings.mappings_dir),
        query=QueryService(ontology, settings),
        analytics=analytics,
        memory=memory,
        context=ContextService(database, ontology, settings, analytics, memory, guardrail),
        webhooks=WebhookService(database, settings),
    )

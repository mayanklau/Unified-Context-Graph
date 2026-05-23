from fastapi import APIRouter

from ucg.api.routes import (
    agents,
    capabilities,
    connectors,
    controls,
    evidence,
    graph,
    health,
    identity,
    ingestion,
    llm_firewall,
    policy,
    privacy,
    risk,
    semantic,
    trust_dlp,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(ingestion.router, prefix="/v1/ingest", tags=["ingestion"])
api_router.include_router(graph.router, prefix="/v1/graph", tags=["graph"])
api_router.include_router(risk.router, prefix="/v1/risk", tags=["risk"])
api_router.include_router(policy.router, prefix="/v1/policy", tags=["policy"])
api_router.include_router(llm_firewall.router, prefix="/v1/llm-firewall", tags=["llm-firewall"])
api_router.include_router(identity.router, prefix="/v1/identity", tags=["identity"])
api_router.include_router(semantic.router, prefix="/v1/semantic", tags=["semantic-layer"])
api_router.include_router(capabilities.router, prefix="/v1/capabilities", tags=["capabilities"])
api_router.include_router(connectors.router, prefix="/v1/connectors", tags=["connectors"])
api_router.include_router(evidence.router, prefix="/v1/evidence", tags=["evidence"])
api_router.include_router(agents.router, prefix="/v1/agents", tags=["agents"])
api_router.include_router(trust_dlp.router, prefix="/v1/trust-dlp", tags=["trust-dlp"])
api_router.include_router(privacy.router, prefix="/v1/privacy", tags=["privacy"])
api_router.include_router(controls.router, prefix="/v1/controls", tags=["controls"])

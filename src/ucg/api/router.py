from fastapi import APIRouter

from ucg.api.routes import graph, health, identity, ingestion, llm_firewall, policy, risk, semantic

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(ingestion.router, prefix="/v1/ingest", tags=["ingestion"])
api_router.include_router(graph.router, prefix="/v1/graph", tags=["graph"])
api_router.include_router(risk.router, prefix="/v1/risk", tags=["risk"])
api_router.include_router(policy.router, prefix="/v1/policy", tags=["policy"])
api_router.include_router(llm_firewall.router, prefix="/v1/llm-firewall", tags=["llm-firewall"])
api_router.include_router(identity.router, prefix="/v1/identity", tags=["identity"])
api_router.include_router(semantic.router, prefix="/v1/semantic", tags=["semantic-layer"])

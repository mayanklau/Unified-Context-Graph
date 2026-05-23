from functools import lru_cache

from ucg.graph.repository import GraphRepository, InMemoryGraphRepository
from ucg.policy.engine import PolicyEngine
from ucg.risk.engine import RiskEngine


@lru_cache
def get_graph_repository() -> GraphRepository:
    return InMemoryGraphRepository()


def get_risk_engine() -> RiskEngine:
    return RiskEngine(get_graph_repository())


def get_policy_engine() -> PolicyEngine:
    return PolicyEngine(get_graph_repository())

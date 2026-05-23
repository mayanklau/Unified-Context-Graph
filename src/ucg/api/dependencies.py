from functools import lru_cache

from ucg.connectors.service import ConnectorRegistry
from ucg.controls.service import ControlLibrary
from ucg.evidence.service import EvidenceVault
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


@lru_cache
def get_evidence_vault() -> EvidenceVault:
    return EvidenceVault()


@lru_cache
def get_connector_registry() -> ConnectorRegistry:
    return ConnectorRegistry()


@lru_cache
def get_control_library() -> ControlLibrary:
    return ControlLibrary()

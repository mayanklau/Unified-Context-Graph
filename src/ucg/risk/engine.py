from ucg.graph.repository import GraphRepository
from ucg.risk.models import (
    RiskScenarioRequest,
    RiskScenarioResponse,
    RiskScoreRequest,
    RiskScoreResponse,
    RiskTier,
)


class RiskEngine:
    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository

    def score(self, request: RiskScoreRequest) -> RiskScoreResponse:
        weighted = (
            request.severity * 0.18
            + request.exploitability * 0.18
            + request.exposure * 0.16
            + request.business_criticality * 0.16
            + request.data_sensitivity * 0.12
            + request.threat_activity * 0.12
            + (1 - request.control_strength) * 0.08
        )
        score = round(weighted * 100, 2)
        context = self.repository.context(request.target_id, request.tenant_id, depth=2)
        return RiskScoreResponse(
            target_id=request.target_id,
            score=score,
            tier=self._tier(score),
            rationale=self._rationale(request),
            evidence_node_ids=[node.id for node in context.nodes if node.id != request.target_id],
        )

    def scenario(self, request: RiskScenarioRequest) -> RiskScenarioResponse:
        weighted = (
            request.likelihood * 0.45
            + request.impact * 0.45
            + (1 - request.control_strength) * 0.10
        )
        score = round(weighted * 100, 2)
        evidence: set[str] = set()
        for target_id in request.target_ids:
            context = self.repository.context(target_id, request.tenant_id, depth=1)
            evidence.update(node.id for node in context.nodes if node.id != target_id)

        rationale = [
            "Scenario score combines likelihood, impact, and residual control weakness.",
            f"Scenario covers {len(request.target_ids)} target(s).",
        ]
        if request.annualized_loss_exposure is not None:
            rationale.append("Annualized loss exposure was supplied by the caller.")

        return RiskScenarioResponse(
            scenario_id=request.scenario_id,
            name=request.name,
            score=score,
            tier=self._tier(score),
            annualized_loss_exposure=request.annualized_loss_exposure,
            rationale=rationale,
            evidence_node_ids=sorted(evidence),
        )

    @staticmethod
    def _tier(score: float) -> RiskTier:
        if score >= 85:
            return RiskTier.CRITICAL
        if score >= 65:
            return RiskTier.HIGH
        if score >= 35:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    @staticmethod
    def _rationale(request: RiskScoreRequest) -> list[str]:
        reasons: list[str] = []
        if request.exploitability >= 0.7:
            reasons.append("High exploitability increases likelihood.")
        if request.exposure >= 0.7:
            reasons.append("High exposure increases attack surface.")
        if request.business_criticality >= 0.7:
            reasons.append("Business-critical target increases impact.")
        if request.data_sensitivity >= 0.7:
            reasons.append("Sensitive data increases impact and regulatory risk.")
        if request.control_strength <= 0.3:
            reasons.append("Weak control strength increases residual risk.")
        if request.threat_activity >= 0.7:
            reasons.append("Active threat activity raises urgency.")
        return reasons or ["Risk is based on balanced likelihood, impact, and control inputs."]

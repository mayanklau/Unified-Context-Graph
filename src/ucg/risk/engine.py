from ucg.graph.repository import GraphRepository
from ucg.risk.models import RiskScoreRequest, RiskScoreResponse, RiskTier


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

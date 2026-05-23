from ucg.graph.repository import GraphRepository
from ucg.policy.models import PolicyDecision, PolicyEvaluationRequest, PolicyOutcome

DESTRUCTIVE_ACTIONS = {"delete", "disable", "exfiltrate", "rotate-secret", "terminate"}
SENSITIVE_CLASSES = {"restricted", "secret", "regulated", "personal_data"}


class PolicyEngine:
    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        reasons: list[str] = []
        required_controls: list[str] = []

        if request.action.lower() in DESTRUCTIVE_ACTIONS and request.risk_score >= 50:
            reasons.append("Destructive action on elevated-risk target requires human review.")
            required_controls.append("human_approval")

        if request.data_classification.lower() in SENSITIVE_CLASSES:
            reasons.append("Sensitive data access requires purpose and least-privilege evidence.")
            required_controls.extend(["purpose_binding", "least_privilege_check"])

        if request.risk_score >= 85:
            reasons.append("Critical risk target blocks autonomous action.")
            outcome = PolicyOutcome.DENY
        elif required_controls:
            outcome = PolicyOutcome.REVIEW
        else:
            reasons.append("No blocking policy condition matched.")
            outcome = PolicyOutcome.ALLOW

        actor_context = self.repository.context(request.actor_id, request.tenant_id, depth=1)
        target_context = self.repository.context(request.target_id, request.tenant_id, depth=1)
        evidence = {node.id for node in actor_context.nodes + target_context.nodes}
        evidence.discard(request.actor_id)
        evidence.discard(request.target_id)

        return PolicyDecision(
            outcome=outcome,
            reasons=reasons,
            required_controls=sorted(set(required_controls)),
            evidence_node_ids=sorted(evidence),
        )

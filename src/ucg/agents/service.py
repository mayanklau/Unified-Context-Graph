from ucg.agents.models import AgentActionEvaluation, AgentActionEvaluationRequest
from ucg.policy.engine import PolicyEngine
from ucg.policy.models import PolicyEvaluationRequest, PolicyOutcome


class AgentGovernanceService:
    def __init__(self, policy_engine: PolicyEngine) -> None:
        self.policy_engine = policy_engine

    def evaluate(self, request: AgentActionEvaluationRequest) -> AgentActionEvaluation:
        decision = self.policy_engine.evaluate(
            PolicyEvaluationRequest(
                actor_id=request.agent_id,
                action=request.action,
                target_id=request.target_id,
                tenant_id=request.tenant_id,
                risk_score=request.risk_score,
                data_classification=request.data_classification,
                attributes={
                    "delegated_by": request.delegated_by,
                    "tool_name": request.tool_name,
                    "purpose": request.purpose,
                },
            )
        )
        approvals = ["human_approval"] if decision.outcome == PolicyOutcome.REVIEW else []
        if decision.outcome == PolicyOutcome.DENY:
            approvals = ["security_owner_exception"]
        return AgentActionEvaluation(
            agent_id=request.agent_id,
            target_id=request.target_id,
            policy_decision=decision,
            trace=[
                "Resolved agent action request.",
                "Evaluated policy with risk, data classification, and graph context.",
            ],
            required_approvals=approvals,
        )

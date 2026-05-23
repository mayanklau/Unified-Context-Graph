from typing import Annotated

from fastapi import APIRouter, Depends

from ucg.agents.models import AgentActionEvaluation, AgentActionEvaluationRequest
from ucg.agents.service import AgentGovernanceService
from ucg.api.dependencies import get_policy_engine
from ucg.policy.engine import PolicyEngine

router = APIRouter()


@router.post("/actions/evaluate", response_model=AgentActionEvaluation)
def evaluate_agent_action(
    request: AgentActionEvaluationRequest,
    policy_engine: Annotated[PolicyEngine, Depends(get_policy_engine)],
) -> AgentActionEvaluation:
    return AgentGovernanceService(policy_engine).evaluate(request)

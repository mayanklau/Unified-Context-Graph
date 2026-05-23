from typing import Annotated

from fastapi import APIRouter, Depends

from ucg.api.dependencies import get_policy_engine
from ucg.policy.engine import PolicyEngine
from ucg.policy.models import PolicyDecision, PolicyEvaluationRequest

router = APIRouter()


@router.post("/evaluate", response_model=PolicyDecision)
def evaluate_policy(
    request: PolicyEvaluationRequest,
    engine: Annotated[PolicyEngine, Depends(get_policy_engine)],
) -> PolicyDecision:
    return engine.evaluate(request)

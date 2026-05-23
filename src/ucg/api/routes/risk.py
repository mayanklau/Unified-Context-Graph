from typing import Annotated

from fastapi import APIRouter, Depends

from ucg.api.dependencies import get_risk_engine
from ucg.risk.engine import RiskEngine
from ucg.risk.models import RiskScoreRequest, RiskScoreResponse

router = APIRouter()


@router.post("/score", response_model=RiskScoreResponse)
def score_risk(
    request: RiskScoreRequest,
    engine: Annotated[RiskEngine, Depends(get_risk_engine)],
) -> RiskScoreResponse:
    return engine.score(request)

from fastapi import APIRouter

from ucg.trust_dlp.engine import TrustDLPEngine
from ucg.trust_dlp.models import TrustDLPEvaluation, TrustDLPEvaluationRequest

router = APIRouter()


@router.post("/evaluate", response_model=TrustDLPEvaluation)
def evaluate_trust_dlp(request: TrustDLPEvaluationRequest) -> TrustDLPEvaluation:
    return TrustDLPEngine().evaluate(signal=request.signal, policies=request.policies)

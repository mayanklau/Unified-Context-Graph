from fastapi import APIRouter

from ucg.privacy.models import PrivacyObligationDecision, PrivacyObligationRequest
from ucg.privacy.service import PrivacyObligationService

router = APIRouter()


@router.post("/obligations/evaluate", response_model=PrivacyObligationDecision)
def evaluate_privacy_obligations(
    request: PrivacyObligationRequest,
) -> PrivacyObligationDecision:
    return PrivacyObligationService().evaluate(request)

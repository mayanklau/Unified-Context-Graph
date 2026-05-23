from fastapi import APIRouter

from ucg.llm_firewall.engine import LLMFirewall
from ucg.llm_firewall.models import FirewallInspectionRequest, FirewallInspectionResponse

router = APIRouter()


@router.post("/inspect", response_model=FirewallInspectionResponse)
def inspect(request: FirewallInspectionRequest) -> FirewallInspectionResponse:
    return LLMFirewall().inspect(request)

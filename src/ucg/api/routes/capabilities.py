from fastapi import APIRouter

from ucg.capabilities import CAPABILITY_ROADMAP, CapabilityArea

router = APIRouter()


@router.get("", response_model=list[CapabilityArea])
def list_capabilities() -> list[CapabilityArea]:
    return CAPABILITY_ROADMAP

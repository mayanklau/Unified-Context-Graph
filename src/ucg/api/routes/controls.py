from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ucg.api.dependencies import get_control_library
from ucg.controls.models import ControlAssessment, ControlFrameworkMapping
from ucg.controls.service import ControlLibrary

router = APIRouter()


@router.post("", response_model=ControlFrameworkMapping)
def upsert_control(
    mapping: ControlFrameworkMapping,
    library: Annotated[ControlLibrary, Depends(get_control_library)],
) -> ControlFrameworkMapping:
    return library.upsert(mapping)


@router.get("", response_model=list[ControlFrameworkMapping])
def list_controls(
    library: Annotated[ControlLibrary, Depends(get_control_library)],
    tenant_id: str = Query("default"),
) -> list[ControlFrameworkMapping]:
    return library.list(tenant_id)


@router.get("/{control_id}/assessment", response_model=ControlAssessment)
def assess_control(
    control_id: str,
    library: Annotated[ControlLibrary, Depends(get_control_library)],
    tenant_id: str = Query("default"),
) -> ControlAssessment:
    return library.assess(control_id, tenant_id)

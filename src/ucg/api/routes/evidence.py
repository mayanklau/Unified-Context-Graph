from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ucg.api.dependencies import get_evidence_vault
from ucg.evidence.models import EvidencePackage, EvidenceRecord
from ucg.evidence.service import EvidenceVault

router = APIRouter()


@router.post("", response_model=EvidenceRecord)
def add_evidence(
    record: EvidenceRecord,
    vault: Annotated[EvidenceVault, Depends(get_evidence_vault)],
) -> EvidenceRecord:
    return vault.add(record)


@router.get("/{evidence_id}", response_model=EvidenceRecord)
def get_evidence(
    evidence_id: str,
    vault: Annotated[EvidenceVault, Depends(get_evidence_vault)],
    tenant_id: str = Query("default"),
) -> EvidenceRecord:
    record = vault.get(evidence_id, tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return record


@router.get("/packages/{subject_id}", response_model=EvidencePackage)
def evidence_package(
    subject_id: str,
    vault: Annotated[EvidenceVault, Depends(get_evidence_vault)],
    tenant_id: str = Query("default"),
) -> EvidencePackage:
    return vault.package_for_subject(subject_id, tenant_id)

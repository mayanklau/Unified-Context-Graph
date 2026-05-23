from ucg.evidence.models import EvidencePackage, EvidenceRecord


class EvidenceVault:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvidenceRecord] = {}

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        self._records[(record.tenant_id, record.id)] = record
        return record

    def get(self, evidence_id: str, tenant_id: str) -> EvidenceRecord | None:
        return self._records.get((tenant_id, evidence_id))

    def package_for_subject(self, subject_id: str, tenant_id: str) -> EvidencePackage:
        return EvidencePackage(
            subject_id=subject_id,
            tenant_id=tenant_id,
            evidence=[
                record
                for (record_tenant, _), record in self._records.items()
                if record_tenant == tenant_id and subject_id in record.subject_ids
            ],
        )

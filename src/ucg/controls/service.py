from ucg.controls.models import ControlAssessment, ControlFrameworkMapping, ControlStatus


class ControlLibrary:
    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], ControlFrameworkMapping] = {}

    def upsert(self, mapping: ControlFrameworkMapping) -> ControlFrameworkMapping:
        self._mappings[(mapping.tenant_id, mapping.control_id)] = mapping
        return mapping

    def list(self, tenant_id: str) -> list[ControlFrameworkMapping]:
        return [
            mapping
            for (mapping_tenant, _), mapping in self._mappings.items()
            if mapping_tenant == tenant_id
        ]

    def assess(self, control_id: str, tenant_id: str) -> ControlAssessment:
        mapping = self._mappings.get((tenant_id, control_id))
        if mapping is None:
            return ControlAssessment(
                control_id=control_id,
                status=ControlStatus.UNKNOWN,
                rationale=["No control mapping or evidence is registered."],
            )
        return ControlAssessment(
            control_id=control_id,
            status=mapping.status,
            rationale=[f"Mapped to {mapping.framework} requirement {mapping.requirement}."],
            evidence_node_ids=mapping.evidence_node_ids,
        )

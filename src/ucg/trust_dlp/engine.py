from ucg.trust_dlp.models import (
    DataMovementSignal,
    DLPDecision,
    TrustDLPEvaluation,
    TrustDLPPolicy,
)


class TrustDLPEngine:
    def evaluate(
        self,
        signal: DataMovementSignal,
        policies: list[TrustDLPPolicy] | None = None,
    ) -> TrustDLPEvaluation:
        policies = policies or []
        findings: list[str] = []
        required_controls: list[str] = []
        decision = signal.recommended_decision

        for policy in policies:
            if policy.blocked_destinations and signal.destination in policy.blocked_destinations:
                findings.append(f"Destination is blocked by policy {policy.id}.")
                decision = DLPDecision.BLOCK

            overlap = set(signal.data_categories).intersection(policy.sensitive_categories)
            if overlap:
                findings.append(
                    f"Sensitive categories {sorted(overlap)} matched policy {policy.id}."
                )
                required_controls.extend(policy.required_controls)
                if signal.purpose not in policy.allowed_purposes:
                    findings.append(f"Purpose is not allowed by policy {policy.id}.")
                    decision = DLPDecision.REVIEW if decision != DLPDecision.BLOCK else decision

        if not findings and signal.data_categories:
            findings.append("Data movement includes classified data but no matching policy.")
            decision = DLPDecision.REVIEW

        if not findings:
            findings.append("No Trust DLP condition matched.")
            decision = DLPDecision.ALLOW

        return TrustDLPEvaluation(
            signal_id=signal.id,
            decision=decision,
            findings=findings,
            required_controls=sorted(set(required_controls)),
            evidence_node_ids=signal.evidence_node_ids,
        )

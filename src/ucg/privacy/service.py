from ucg.privacy.models import PrivacyObligationDecision, PrivacyObligationRequest


class PrivacyObligationService:
    def evaluate(self, request: PrivacyObligationRequest) -> PrivacyObligationDecision:
        obligations: list[str] = []
        controls: list[str] = []
        rationale: list[str] = []

        if request.data_categories:
            obligations.append("data_inventory")
            controls.append("purpose_binding")
            rationale.append("Data categories require inventory and purpose binding.")

        if request.transfer_regions:
            obligations.append("cross_border_transfer_review")
            controls.append("transfer_impact_assessment")
            rationale.append("Transfer regions require residency and transfer review.")

        if any(category.value == "customer" for category in request.subject_categories):
            obligations.append("data_subject_request_readiness")
            controls.append("dsar_workflow")
            rationale.append("Customer data requires data subject rights readiness.")

        if not obligations:
            rationale.append("No additional privacy obligation matched the request context.")

        return PrivacyObligationDecision(
            activity_id=request.activity_id,
            obligations=sorted(set(obligations)),
            required_controls=sorted(set(controls)),
            rationale=rationale,
        )

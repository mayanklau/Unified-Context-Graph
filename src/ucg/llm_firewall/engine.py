import re

from ucg.llm_firewall.models import (
    FirewallDecision,
    FirewallFinding,
    FirewallInspectionRequest,
    FirewallInspectionResponse,
)

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"]?[\w\-]{12,}"),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"),
]

INJECTION_MARKERS = [
    "ignore previous instructions",
    "developer message",
    "system prompt",
    "bypass policy",
    "disable guardrails",
]

DESTRUCTIVE_TOOL_MARKERS = [
    "rm -rf",
    "drop database",
    "delete all",
    "disable logging",
]


class LLMFirewall:
    def inspect(self, request: FirewallInspectionRequest) -> FirewallInspectionResponse:
        content_lower = request.content.lower()
        findings: list[FirewallFinding] = []

        if any(marker in content_lower for marker in INJECTION_MARKERS):
            findings.append(
                FirewallFinding(
                    category="prompt_injection",
                    severity="high",
                    reason="Content attempts to override governing instructions or policy.",
                )
            )

        if any(pattern.search(request.content) for pattern in SECRET_PATTERNS):
            findings.append(
                FirewallFinding(
                    category="secret_exposure",
                    severity="critical",
                    reason="Content appears to contain credential or secret material.",
                )
            )

        if any(marker in content_lower for marker in DESTRUCTIVE_TOOL_MARKERS):
            findings.append(
                FirewallFinding(
                    category="unsafe_tool_use",
                    severity="high",
                    reason="Content references destructive tool behavior.",
                )
            )

        if not findings:
            return FirewallInspectionResponse(decision=FirewallDecision.ALLOW, findings=[])

        severities = {finding.severity for finding in findings}
        if "critical" in severities:
            decision = FirewallDecision.BLOCK
        elif "restricted" in request.context_labels or "regulated" in request.context_labels:
            decision = FirewallDecision.REVIEW
        else:
            decision = FirewallDecision.REDACT

        return FirewallInspectionResponse(
            decision=decision,
            findings=findings,
            recommended_controls=["redaction", "human_review", "policy_trace"],
        )

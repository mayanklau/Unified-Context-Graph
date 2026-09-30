"""Protective-plane hook and local content hygiene.

The graph accepts free text from agents (memory notes) and hands graph content
back to agents (context packs). Both directions can be routed through the
organisation's protective plane — AgentPEP, the LLM Firewall or Thoth — using
the same webhook contract as the Agentic SOC Harness:

    POST {"stage": "...", "payload": {...}, "meta": {...}}
    ←    {"allow": true|false, "reason": "...", "payload": {...optional replacement...}}

Independently of any webhook, obvious secrets are redacted before text is stored.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from secgraph.config import Settings
from secgraph.errors import GuardrailBlocked
from secgraph.observability import GUARDRAIL_DECISIONS, get_logger

log = get_logger(__name__)

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("api_key", re.compile(r"\bsg_[0-9a-f]{12}_[A-Za-z0-9_-]{40,64}\b")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@")),
    (
        "assigned_secret",
        re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b(\s*[:=]\s*)(\S{6,})"),
    ),
]


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Replace credential-shaped substrings. Returns the cleaned text and what was found."""
    found: list[str] = []

    for label, pattern in _SECRET_PATTERNS:
        if label == "url_credentials":
            text, count = pattern.subn(lambda m: f"{m.group(1)}[REDACTED]@", text)
        elif label == "assigned_secret":
            text, count = pattern.subn(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text, count = pattern.subn(f"[REDACTED:{label}]", text)
        if count:
            found.append(label)
    return text, found


class Guardrail:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.url = settings.guardrail_webhook_url
        self.fail_closed = settings.guardrail_fail_closed
        self._client = client or (httpx.Client(timeout=settings.guardrail_timeout_s) if self.url else None)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def check(self, stage: str, payload: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        """Ask the protective plane. Returns the (possibly rewritten) payload or raises ``GuardrailBlocked``."""
        if not self.url or self._client is None:
            return payload
        try:
            response = self._client.post(self.url, json={"stage": stage, "payload": payload, "meta": meta})
            response.raise_for_status()
            verdict = response.json()
            if not isinstance(verdict, dict) or not isinstance(verdict.get("allow"), bool):
                raise ValueError("verdict must be an object with a boolean 'allow'")
        except Exception as exc:
            GUARDRAIL_DECISIONS.labels(stage=stage, decision="error").inc()
            log.error("protective plane unreachable", stage=stage, error=str(exc)[:300])
            if self.fail_closed:
                raise GuardrailBlocked(
                    "the protective plane could not be reached and the service is configured to fail closed"
                ) from exc
            return payload
        if not verdict["allow"]:
            GUARDRAIL_DECISIONS.labels(stage=stage, decision="block").inc()
            raise GuardrailBlocked(str(verdict.get("reason") or "blocked by policy")[:500])
        GUARDRAIL_DECISIONS.labels(stage=stage, decision="allow").inc()
        replacement = verdict.get("payload")
        return replacement if isinstance(replacement, dict) else payload

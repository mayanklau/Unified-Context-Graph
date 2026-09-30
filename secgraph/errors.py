"""Typed errors. The API layer maps each to an HTTP status; nothing else
should raise bare ``Exception`` for an expected condition."""

from __future__ import annotations

from typing import Any


class SecGraphError(Exception):
    """Base class. ``code`` is a stable machine-readable identifier."""

    status = 500
    code = "internal_error"

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class ConfigurationError(SecGraphError):
    status = 500
    code = "configuration_error"


class OntologyError(SecGraphError):
    """The ontology file itself is invalid."""

    status = 500
    code = "ontology_error"


class ValidationFailed(SecGraphError):
    """A record or request does not conform to the ontology or API contract."""

    status = 422
    code = "validation_failed"


class NotFound(SecGraphError):
    status = 404
    code = "not_found"


class Conflict(SecGraphError):
    status = 409
    code = "conflict"


class AuthenticationError(SecGraphError):
    status = 401
    code = "unauthenticated"


class PermissionDenied(SecGraphError):
    status = 403
    code = "permission_denied"


class RateLimited(SecGraphError):
    status = 429
    code = "rate_limited"


class LimitExceeded(SecGraphError):
    """A query or analytic would exceed a configured safety limit."""

    status = 413
    code = "limit_exceeded"


class GuardrailBlocked(SecGraphError):
    """The protective plane (AgentPEP / LLM Firewall / Thoth) refused the content."""

    status = 403
    code = "guardrail_blocked"


class RetryableWrite(SecGraphError):
    """A concurrent writer won a race; the caller should retry the unit of work."""

    status = 503
    code = "retryable_write"

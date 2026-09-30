"""Request dependencies: application context, authentication, authorisation, common parameters."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, Header, Query, Request

from secgraph.context import AppContext
from secgraph.errors import PermissionDenied, ValidationFailed
from secgraph.governance.auth import validate_tenant_id
from secgraph.governance.rbac import Principal
from secgraph.observability import principal_var, tenant_var
from secgraph.ontology.validate import parse_datetime
from secgraph.store.types import utcnow


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


Ctx = Annotated[AppContext, Depends(get_ctx)]


def get_principal(
    request: Request,
    ctx: Ctx,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> Principal:
    principal = ctx.auth.authenticate(authorization, x_api_key)
    if x_tenant_id and x_tenant_id != principal.tenant_id:
        if not principal.can("admin:tenants"):
            raise PermissionDenied("only a platform administrator may act on another tenant")
        tenant = validate_tenant_id(x_tenant_id.strip().lower())
        principal = Principal.build(
            id=principal.id,
            name=principal.name,
            kind=principal.kind,
            tenant_id=tenant,
            roles=list(principal.roles),
            node_types=list(principal.node_types) if principal.node_types is not None else None,
        )
    ctx.limiter.check(principal.id)
    tenant_var.set(principal.tenant_id)
    principal_var.set(principal.id)
    request.state.principal = principal
    return principal


Caller = Annotated[Principal, Depends(get_principal)]


def require(permission: str) -> Callable[[Principal], Principal]:
    """Dependency factory: the caller must hold ``permission``."""

    def _check(principal: Caller) -> Principal:
        principal.require(permission)
        return principal

    return _check


def require_analytics(principal: Caller) -> Principal:
    principal.require("analytics:read")
    principal.require_full_graph("analytics")
    return principal


def as_of_param(
    as_of: Annotated[
        str | None,
        Query(description="Read the graph as it was at this time (ISO 8601). Omit for the current state."),
    ] = None,
) -> datetime | None:
    if as_of is None:
        return None
    try:
        moment = parse_datetime(as_of)
    except ValueError as exc:
        raise ValidationFailed(f"as_of: {exc}") from exc
    if moment > utcnow():
        raise ValidationFailed("as_of must not be in the future")
    return moment


AsOf = Annotated[datetime | None, Depends(as_of_param)]


def json_param(name: str, raw: str | None) -> Any:
    if raw is None or raw == "":
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationFailed(f"'{name}' must be JSON: {exc.msg}") from exc


def csv_param(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    values = [v.strip() for v in raw.split(",") if v.strip()]
    return values or None

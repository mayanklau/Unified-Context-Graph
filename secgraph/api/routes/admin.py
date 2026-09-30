"""Administration: users, API keys, webhooks, audit, change feed, export."""

from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response

from secgraph.agents.vault import export_vault
from secgraph.api.deps import Ctx, csv_param, require
from secgraph.api.schemas import ApiKeyBody, UserCreateBody, UserUpdateBody, WebhookBody, WebhookStateBody
from secgraph.events.outbox import event_payload, head_sequence, read_changes
from secgraph.governance import audit
from secgraph.governance.rbac import PERMISSIONS, ROLES, Principal

router = APIRouter(prefix="/api/v1", tags=["admin"])


@router.get("/roles", summary="Roles and the permissions each grants")
def roles(principal: Annotated[Principal, Depends(require("graph:read"))]) -> dict[str, Any]:
    return {"roles": {name: sorted(perms) for name, perms in ROLES.items()}, "permissions": PERMISSIONS}


# ---- users ------------------------------------------------------------------
UserAdmin = Annotated[Principal, Depends(require("admin:users"))]


@router.get("/users", summary="List users")
def list_users(ctx: Ctx, principal: UserAdmin) -> dict[str, Any]:
    return {"items": ctx.auth.list_users(principal.tenant_id)}


@router.post("/users", summary="Create a user", status_code=201)
def create_user(body: UserCreateBody, ctx: Ctx, principal: UserAdmin) -> dict[str, Any]:
    return ctx.auth.create_user(
        principal.tenant_id,
        principal.id,
        username=body.username,
        password=body.password,
        roles=body.roles,
        allow_platform_admin=principal.can("admin:tenants"),
    )


@router.patch("/users/{username}", summary="Change a user's roles, password or disabled state")
def update_user(username: str, body: UserUpdateBody, ctx: Ctx, principal: UserAdmin) -> dict[str, Any]:
    return ctx.auth.update_user(
        principal.tenant_id,
        principal.id,
        username,
        roles=body.roles,
        disabled=body.disabled,
        password=body.password,
        allow_platform_admin=principal.can("admin:tenants"),
    )


# ---- API keys ---------------------------------------------------------------
KeyAdmin = Annotated[Principal, Depends(require("admin:keys"))]


@router.get("/api-keys", summary="List API keys (never the key itself)")
def list_keys(ctx: Ctx, principal: KeyAdmin) -> dict[str, Any]:
    return {"items": ctx.auth.list_api_keys(principal.tenant_id)}


@router.post("/api-keys", summary="Create an API key; the key is shown once", status_code=201)
def create_key(body: ApiKeyBody, ctx: Ctx, principal: KeyAdmin) -> dict[str, Any]:
    return ctx.auth.create_api_key(
        principal.tenant_id,
        principal.id,
        name=body.name,
        roles=body.roles,
        kind=body.kind,
        node_types=body.node_types,
        expires_in_days=body.expires_in_days,
        known_node_types=set(ctx.ontology.node_types),
    )


@router.delete("/api-keys/{key_id}", summary="Revoke an API key", status_code=204)
def revoke_key(key_id: str, ctx: Ctx, principal: KeyAdmin) -> Response:
    ctx.auth.revoke_api_key(principal.tenant_id, principal.id, key_id)
    return Response(status_code=204)


# ---- webhooks ---------------------------------------------------------------
HookAdmin = Annotated[Principal, Depends(require("admin:webhooks"))]


@router.get("/webhooks", summary="List webhook subscriptions")
def list_webhooks(ctx: Ctx, principal: HookAdmin) -> dict[str, Any]:
    return {"items": ctx.webhooks.list(principal.tenant_id)}


@router.post("/webhooks", summary="Subscribe a URL to graph changes; the signing secret is shown once", status_code=201)
def create_webhook(body: WebhookBody, ctx: Ctx, principal: HookAdmin) -> dict[str, Any]:
    return ctx.webhooks.create(
        principal.tenant_id,
        principal.id,
        name=body.name,
        url=body.url,
        event_kinds=body.event_kinds,
        entity_types=body.entity_types,
        from_now=body.from_now,
        known_types=set(ctx.ontology.node_types) | set(ctx.ontology.edge_types),
    )


@router.patch("/webhooks/{hook_id}", summary="Enable or disable a subscription")
def set_webhook_state(hook_id: str, body: WebhookStateBody, ctx: Ctx, principal: HookAdmin) -> dict[str, Any]:
    return ctx.webhooks.set_active(principal.tenant_id, principal.id, hook_id, body.active)


@router.delete("/webhooks/{hook_id}", summary="Delete a subscription", status_code=204)
def delete_webhook(hook_id: str, ctx: Ctx, principal: HookAdmin) -> Response:
    ctx.webhooks.delete(principal.tenant_id, principal.id, hook_id)
    return Response(status_code=204)


# ---- change feed ------------------------------------------------------------
@router.get("/changes", tags=["changes"], summary="Ordered change feed; resume with the last sequence you saw")
def changes(
    ctx: Ctx,
    principal: Annotated[Principal, Depends(require("changes:read"))],
    after: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    kind: Annotated[str | None, Query(description="Comma-separated event kinds")] = None,
    entity_type: Annotated[str | None, Query(description="Comma-separated node or edge types")] = None,
) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        events = read_changes(
            session,
            principal.tenant_id,
            after=after,
            limit=limit,
            kinds=csv_param(kind),
            entity_types=csv_param(entity_type),
        )
        head = head_sequence(session, principal.tenant_id)
    if principal.scope.unrestricted:
        visible = events
    else:
        # A type-restricted caller sees node events for its types only; an edge event names no endpoint
        # types, so it cannot be shown without risking a leak.
        visible = [e for e in events if e.kind.startswith("node.") and principal.scope.allows(e.entity_type)]
    return {
        "items": [event_payload(e) for e in visible],
        "cursor": events[-1].seq if events else after,
        "head": head,
    }


# ---- audit ------------------------------------------------------------------
Auditor = Annotated[Principal, Depends(require("audit:read"))]


@router.get("/audit", tags=["audit"], summary="Audit log, newest first")
def audit_log(
    ctx: Ctx,
    principal: Auditor,
    before: Annotated[int | None, Query(ge=1)] = None,
    action: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        rows = audit.list_entries(session, principal.tenant_id, before=before, action=action, limit=limit)
        return {
            "items": [
                {
                    "seq": r.seq,
                    "ts": r.ts.isoformat(),
                    "actor": r.actor,
                    "action": r.action,
                    "target": r.target,
                    "detail": r.detail,
                    "request_id": r.request_id,
                    "hash": r.hash,
                }
                for r in rows
            ]
        }


@router.get("/audit/verify", tags=["audit"], summary="Recompute the audit hash chain")
def audit_verify(ctx: Ctx, principal: Auditor) -> dict[str, Any]:
    with ctx.db.snapshot() as session:
        return audit.verify(session, principal.tenant_id)


# ---- export -----------------------------------------------------------------
@router.get("/export/vault", tags=["agents"], summary="The graph as a Markdown vault (tar.gz) for file-based agents")
def vault(
    ctx: Ctx,
    principal: Annotated[Principal, Depends(require("graph:read"))],
    max_nodes: Annotated[int, Query(ge=1, le=50000)] = 5000,
) -> Response:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder) / "security-graph-vault"
        export_vault(ctx, principal, root, max_nodes=max_nodes)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(root, arcname=root.name)
    return Response(
        buffer.getvalue(),
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="security-graph-vault.tar.gz"'},
    )

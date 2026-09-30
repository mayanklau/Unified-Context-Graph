"""Roles, permissions and data scope.

A principal is a human (JWT), a service or an agent (API key). Roles grant
permissions; an API key can additionally be confined to a subset of node
types. Personal data is masked unless the principal holds ``pii:read``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secgraph.errors import PermissionDenied

# permission -> what it allows
PERMISSIONS: dict[str, str] = {
    "graph:read": "Read nodes, edges, history and run graph queries",
    "graph:write": "Ingest and retract graph data",
    "graph:curate": "Merge entities, resolve conflicts, replay or discard quarantined records",
    "analytics:read": "Run attack-path, blast-radius and prioritisation analytics",
    "memory:read": "Read shared agent/analyst memory",
    "memory:write": "Write to shared memory and record outcomes",
    "pii:read": "See personal data unmasked",
    "changes:read": "Read the change feed",
    "audit:read": "Read and verify the audit log",
    "admin:keys": "Create and revoke API keys",
    "admin:users": "Create, disable and re-role users",
    "admin:webhooks": "Manage webhook subscriptions",
    "admin:tenants": "Act on any tenant (platform operators only)",
}

ROLES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"graph:read"}),
    "analyst": frozenset({"graph:read", "analytics:read", "memory:read", "memory:write", "pii:read"}),
    "agent": frozenset({"graph:read", "analytics:read", "memory:read", "memory:write"}),
    "ingest": frozenset({"graph:write"}),
    "steward": frozenset({"graph:read", "graph:write", "graph:curate", "pii:read"}),
    "integration": frozenset({"graph:read", "analytics:read", "changes:read"}),
    "auditor": frozenset({"graph:read", "audit:read", "changes:read"}),
    "admin": frozenset(set(PERMISSIONS) - {"admin:tenants"}),
    "platform_admin": frozenset(PERMISSIONS),
}


def permissions_for(roles: list[str] | tuple[str, ...]) -> frozenset[str]:
    granted: set[str] = set()
    for role in roles:
        granted |= ROLES.get(role, frozenset())
    return frozenset(granted)


def validate_roles(roles: list[str]) -> list[str]:
    unknown = sorted(set(roles) - set(ROLES))
    if unknown:
        from secgraph.errors import ValidationFailed

        raise ValidationFailed(f"unknown role(s): {', '.join(unknown)}; known: {', '.join(sorted(ROLES))}")
    return list(dict.fromkeys(roles))


@dataclass(frozen=True)
class AccessScope:
    """What a principal may see. ``node_types=None`` means every type."""

    node_types: frozenset[str] | None = None
    pii: bool = False

    def allows(self, node_type: str) -> bool:
        return self.node_types is None or node_type in self.node_types

    def restrict(self, requested: list[str] | None, all_types: list[str]) -> list[str] | None:
        """Intersect a requested type filter with the scope. ``None`` = no filter needed."""
        if self.node_types is None:
            return requested
        allowed = [t for t in all_types if t in self.node_types]
        if requested is None:
            return allowed
        return [t for t in requested if t in self.node_types]

    @property
    def unrestricted(self) -> bool:
        return self.node_types is None


FULL_SCOPE = AccessScope(node_types=None, pii=True)


@dataclass(frozen=True)
class Principal:
    id: str  # "user:alice", "key:<key id>"
    name: str
    kind: str  # user | service | agent
    tenant_id: str
    roles: tuple[str, ...] = ()
    node_types: frozenset[str] | None = None
    permissions: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def build(
        cls,
        *,
        id: str,
        name: str,
        kind: str,
        tenant_id: str,
        roles: list[str] | tuple[str, ...],
        node_types: list[str] | None = None,
    ) -> Principal:
        return cls(
            id=id,
            name=name,
            kind=kind,
            tenant_id=tenant_id,
            roles=tuple(roles),
            node_types=frozenset(node_types) if node_types is not None else None,
            permissions=permissions_for(tuple(roles)),
        )

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise PermissionDenied(f"this action needs the '{permission}' permission")

    @property
    def scope(self) -> AccessScope:
        return AccessScope(node_types=self.node_types, pii="pii:read" in self.permissions)

    def require_full_graph(self, what: str) -> None:
        """Analytics reason over the whole graph; a type-restricted principal cannot run them."""
        if self.node_types is not None:
            raise PermissionDenied(f"{what} needs access to every node type; this credential is restricted")

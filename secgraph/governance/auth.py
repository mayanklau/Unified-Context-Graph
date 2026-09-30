"""Authentication.

* Humans log in with a password and receive a short-lived JWT (HS256), or
  present a token issued by the organisation's identity provider (RS256/ES256,
  verified against a configured public key).
* Services and agents use API keys. Only a SHA-256 digest of each key is
  stored; the key itself is shown once, at creation.

Users and keys are re-checked against the database on every request, so
disabling a user or revoking a key takes effect immediately.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import AuthenticationError, ConfigurationError, Conflict, NotFound, ValidationFailed
from secgraph.governance import audit
from secgraph.governance.rbac import Principal, validate_roles
from secgraph.observability import AUTH_EVENTS, get_logger
from secgraph.store.db import Database, ensure_tenant
from secgraph.store.models import ApiKey, User
from secgraph.store.types import utcnow

log = get_logger(__name__)

_PBKDF2_ITERATIONS = 600_000
_KEY_RE = re.compile(r"^sg_([0-9a-f]{12})_([A-Za-z0-9_-]{40,64})$")
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,126}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$")
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_EXTERNAL_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
_MIN_PASSWORD_LENGTH = 12
_LAST_USED_GRANULARITY = timedelta(minutes=5)
# A fixed hash to burn the same CPU time when the username does not exist.
_DUMMY_HASH = "pbkdf2_sha256$600000$AAAAAAAAAAAAAAAAAAAAAA==$" + base64.b64encode(b"\x00" * 32).decode()


def hash_password(password: str, *, iterations: int | None = None) -> str:
    iterations = iterations or _PBKDF2_ITERATIONS
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)


def check_password_strength(password: str) -> None:
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValidationFailed(f"passwords must be at least {_MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        raise ValidationFailed("passwords must be at most 256 characters")
    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        raise ValidationFailed("passwords need three of: lower case, upper case, digit, symbol")


def validate_tenant_id(tenant_id: str) -> str:
    if not _TENANT_RE.match(tenant_id):
        raise ValidationFailed("tenant ids are 1-63 characters of a-z, 0-9, '_' or '-'")
    return tenant_id


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings
        self._public_key: str | None = None
        if settings.oidc_public_key_file:
            path = Path(settings.oidc_public_key_file)
            if not path.is_file():
                raise ConfigurationError(f"SECGRAPH_OIDC_PUBLIC_KEY_FILE not found: {path}")
            self._public_key = path.read_text(encoding="utf-8")
            if not settings.oidc_issuer:
                raise ConfigurationError("SECGRAPH_OIDC_ISSUER must be set when an OIDC public key is configured")

    # ------------------------------------------------------------------ #
    # Bootstrap
    # ------------------------------------------------------------------ #
    def bootstrap(self) -> None:
        """Development convenience: create ``admin`` from SECGRAPH_BOOTSTRAP_ADMIN_PASSWORD if absent."""
        password = self.settings.bootstrap_admin_password
        if not password:
            return
        if self.settings.is_production():
            raise ConfigurationError("SECGRAPH_BOOTSTRAP_ADMIN_PASSWORD is not allowed in production")

        def _work(session: Session) -> None:
            ensure_tenant(session, self.settings.default_tenant)
            existing = session.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
            if existing is None:
                session.add(
                    User(
                        id=uuid.uuid4().hex,
                        tenant_id=self.settings.default_tenant,
                        username="admin",
                        password_hash=hash_password(password),
                        roles=["platform_admin"],
                    )
                )
                log.warning("created development bootstrap user 'admin'")

        self.db.run(_work)

    # ------------------------------------------------------------------ #
    # Passwords and tokens
    # ------------------------------------------------------------------ #
    def login(self, username: str, password: str) -> dict[str, Any]:
        username = username.strip().lower()

        def _work(session: Session) -> tuple[Principal | None, str]:
            user = session.execute(
                select(User).where(User.username == username).with_for_update()
            ).scalar_one_or_none()
            now = utcnow()
            if user is None:
                verify_password(password, _DUMMY_HASH)
                return None, "unknown"
            if user.locked_until is not None and user.locked_until > now:
                return None, "locked"
            if user.disabled or not verify_password(password, user.password_hash):
                user.failed_attempts += 1
                if user.failed_attempts >= self.settings.login_max_failures:
                    user.locked_until = now + timedelta(seconds=self.settings.login_lockout_seconds)
                    user.failed_attempts = 0
                    audit.record(
                        session, user.tenant_id, actor=f"user:{username}", action="auth.lockout",
                        target=f"user:{username}",
                    )
                return None, "invalid"
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login_at = now
            audit.record(session, user.tenant_id, actor=f"user:{username}", action="auth.login")
            return (
                Principal.build(
                    id=f"user:{user.username}", name=user.username, kind="user", tenant_id=user.tenant_id,
                    roles=list(user.roles or []),
                ),
                "ok",
            )

        principal, outcome = self.db.run(_work)
        AUTH_EVENTS.labels(outcome=f"login_{outcome}").inc()
        if principal is None:
            log.warning("login failed", username=username, outcome=outcome)
            # One message for every failure: do not reveal whether the account exists or is locked.
            raise AuthenticationError("invalid credentials")
        now = int(time.time())
        claims = {
            "iss": self.settings.jwt_issuer,
            "sub": principal.id,
            "tenant": principal.tenant_id,
            "roles": list(principal.roles),
            "iat": now,
            "exp": now + self.settings.jwt_ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        token = jwt.encode(claims, self.settings.jwt_secret, algorithm="HS256")
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": self.settings.jwt_ttl_seconds,
            "tenant": principal.tenant_id,
            "roles": list(principal.roles),
        }

    def _principal_from_jwt(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("malformed token") from exc
        algorithm = header.get("alg")
        try:
            if algorithm == "HS256":
                claims = jwt.decode(
                    token,
                    self.settings.jwt_secret,
                    algorithms=["HS256"],
                    issuer=self.settings.jwt_issuer,
                    options={"require": ["exp", "iat", "sub", "iss"]},
                )
                subject = str(claims["sub"])
                if not subject.startswith("user:"):
                    raise AuthenticationError("unsupported token subject")
                return self._load_user_principal(subject.removeprefix("user:"))
            if algorithm in _EXTERNAL_ALGORITHMS and self._public_key:
                claims = jwt.decode(
                    token,
                    self._public_key,
                    algorithms=_EXTERNAL_ALGORITHMS,
                    issuer=self.settings.oidc_issuer,
                    audience=self.settings.oidc_audience,
                    options={
                        "require": ["exp", "sub", "iss"],
                        "verify_aud": self.settings.oidc_audience is not None,
                    },
                )
                return self._external_principal(claims)
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid token: {exc}") from exc
        raise AuthenticationError("unsupported token algorithm")

    def _load_user_principal(self, username: str) -> Principal:
        with self.db.transaction() as session:
            user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None or user.disabled:
                raise AuthenticationError("account is disabled or no longer exists")
            return Principal.build(
                id=f"user:{user.username}", name=user.username, kind="user", tenant_id=user.tenant_id,
                roles=list(user.roles or []),
            )

    def _external_principal(self, claims: dict[str, Any]) -> Principal:
        raw_roles = claims.get(self.settings.oidc_roles_claim, [])
        if isinstance(raw_roles, str):
            raw_roles = raw_roles.split()
        from secgraph.governance.rbac import ROLES

        roles = [r for r in raw_roles if isinstance(r, str) and r in ROLES and r != "platform_admin"]
        tenant = claims.get(self.settings.oidc_tenant_claim) or self.settings.default_tenant
        if not isinstance(tenant, str) or not _TENANT_RE.match(tenant):
            raise AuthenticationError("token carries an invalid tenant")
        subject = str(claims["sub"])[:100]
        name = str(claims.get("preferred_username") or claims.get("email") or subject)[:128]
        return Principal.build(id=f"oidc:{subject}", name=name, kind="user", tenant_id=tenant, roles=roles)

    # ------------------------------------------------------------------ #
    # API keys
    # ------------------------------------------------------------------ #
    def _principal_from_api_key(self, key: str) -> Principal:
        match = _KEY_RE.match(key)
        if not match:
            raise AuthenticationError("malformed API key")
        prefix = match.group(1)
        with self.db.transaction() as session:
            row = session.execute(select(ApiKey).where(ApiKey.prefix == prefix)).scalar_one_or_none()
            digest = _digest(key)
            if row is None:
                hmac.compare_digest(digest, "0" * 64)
                raise AuthenticationError("invalid API key")
            if not hmac.compare_digest(digest, row.key_hash):
                raise AuthenticationError("invalid API key")
            now = utcnow()
            if row.revoked_at is not None:
                raise AuthenticationError("API key has been revoked")
            if row.expires_at is not None and row.expires_at <= now:
                raise AuthenticationError("API key has expired")
            if row.last_used_at is None or now - row.last_used_at > _LAST_USED_GRANULARITY:
                row.last_used_at = now
            return Principal.build(
                id=f"key:{row.id}",
                name=row.name,
                kind=row.kind,
                tenant_id=row.tenant_id,
                roles=list(row.roles or []),
                node_types=list(row.node_types) if row.node_types is not None else None,
            )

    def authenticate(self, authorization: str | None, api_key: str | None) -> Principal:
        """Resolve the caller from ``Authorization: Bearer …`` or ``X-API-Key``."""
        try:
            if api_key:
                principal = self._principal_from_api_key(api_key.strip())
            elif authorization:
                scheme, _, credential = authorization.partition(" ")
                credential = credential.strip()
                if scheme.lower() != "bearer" or not credential:
                    raise AuthenticationError("use 'Authorization: Bearer <token>'")
                if credential.startswith("sg_"):
                    principal = self._principal_from_api_key(credential)
                else:
                    principal = self._principal_from_jwt(credential)
            else:
                raise AuthenticationError("authentication required")
        except AuthenticationError:
            AUTH_EVENTS.labels(outcome="rejected").inc()
            raise
        AUTH_EVENTS.labels(outcome="accepted").inc()
        return principal

    def create_api_key(
        self,
        tenant_id: str,
        created_by: str,
        *,
        name: str,
        roles: list[str],
        kind: str = "service",
        node_types: list[str] | None = None,
        expires_in_days: int | None = None,
        known_node_types: set[str] | None = None,
    ) -> dict[str, Any]:
        if not _NAME_RE.match(name):
            raise ValidationFailed("key names are 1-128 characters: letters, digits, space and . _ : / -")
        if kind not in ("service", "agent"):
            raise ValidationFailed("kind must be 'service' or 'agent'")
        roles = validate_roles(roles)
        if not roles:
            raise ValidationFailed("at least one role is required")
        if "platform_admin" in roles:
            raise ValidationFailed("API keys cannot hold the platform_admin role")
        if node_types is not None:
            if not node_types:
                raise ValidationFailed("node_types must not be empty; omit it to allow every type")
            unknown = sorted(set(node_types) - (known_node_types or set(node_types)))
            if unknown:
                raise ValidationFailed(f"unknown node type(s): {', '.join(unknown)}")
        if expires_in_days is not None and not 1 <= expires_in_days <= 3650:
            raise ValidationFailed("expires_in_days must be between 1 and 3650")
        prefix = secrets.token_hex(6)
        key = f"sg_{prefix}_{secrets.token_urlsafe(32)}"
        key_id = uuid.uuid4().hex
        now = utcnow()

        def _work(session: Session) -> None:
            ensure_tenant(session, tenant_id)
            session.add(
                ApiKey(
                    id=key_id,
                    tenant_id=tenant_id,
                    name=name,
                    prefix=prefix,
                    key_hash=_digest(key),
                    kind=kind,
                    roles=roles,
                    node_types=sorted(set(node_types)) if node_types is not None else None,
                    created_by=created_by,
                    created_at=now,
                    expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
                )
            )
            audit.record(
                session, tenant_id, actor=created_by, action="apikey.create", target=f"key:{key_id}",
                detail={"name": name, "roles": roles, "kind": kind, "node_types": node_types},
            )

        self.db.run(_work)
        return {
            "id": key_id,
            "name": name,
            "kind": kind,
            "roles": roles,
            "node_types": node_types,
            "expires_at": (now + timedelta(days=expires_in_days)).isoformat() if expires_in_days else None,
            "api_key": key,
        }

    def revoke_api_key(self, tenant_id: str, actor: str, key_id: str) -> None:
        def _work(session: Session) -> None:
            row = session.execute(
                select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.id == key_id)
            ).scalar_one_or_none()
            if row is None:
                raise NotFound(f"API key {key_id} does not exist")
            if row.revoked_at is None:
                row.revoked_at = utcnow()
                audit.record(session, tenant_id, actor=actor, action="apikey.revoke", target=f"key:{key_id}")

        self.db.run(_work)

    def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.db.transaction() as session:
            rows = session.execute(
                select(ApiKey).where(ApiKey.tenant_id == tenant_id).order_by(ApiKey.created_at.desc())
            ).scalars()
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "kind": r.kind,
                    "prefix": f"sg_{r.prefix}_…",
                    "roles": r.roles,
                    "node_types": r.node_types,
                    "created_by": r.created_by,
                    "created_at": r.created_at.isoformat(),
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                    "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                }
                for r in rows
            ]

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    def create_user(
        self, tenant_id: str, actor: str, *, username: str, password: str, roles: list[str],
        allow_platform_admin: bool = False,
    ) -> dict[str, Any]:
        username = username.strip().lower()
        if not _USERNAME_RE.match(username):
            raise ValidationFailed("usernames are 2-127 characters of a-z, 0-9 and . _ @ -")
        check_password_strength(password)
        roles = validate_roles(roles)
        if "platform_admin" in roles and not allow_platform_admin:
            raise ValidationFailed("only a platform administrator can grant platform_admin")
        user_id = uuid.uuid4().hex
        password_hash = hash_password(password)

        def _work(session: Session) -> None:
            ensure_tenant(session, tenant_id)
            if session.execute(select(User.id).where(User.username == username)).first() is not None:
                raise Conflict(f"user '{username}' already exists")
            session.add(
                User(id=user_id, tenant_id=tenant_id, username=username, password_hash=password_hash, roles=roles)
            )
            audit.record(
                session, tenant_id, actor=actor, action="user.create", target=f"user:{username}",
                detail={"roles": roles},
            )

        self.db.run(_work)
        return {"id": user_id, "username": username, "roles": roles, "tenant": tenant_id}

    def update_user(
        self,
        tenant_id: str,
        actor: str,
        username: str,
        *,
        roles: list[str] | None = None,
        disabled: bool | None = None,
        password: str | None = None,
        allow_platform_admin: bool = False,
    ) -> dict[str, Any]:
        username = username.strip().lower()
        if roles is not None:
            roles = validate_roles(roles)
            if "platform_admin" in roles and not allow_platform_admin:
                raise ValidationFailed("only a platform administrator can grant platform_admin")
        password_hash = None
        if password is not None:
            check_password_strength(password)
            password_hash = hash_password(password)

        def _work(session: Session) -> dict[str, Any]:
            user = session.execute(
                select(User).where(User.tenant_id == tenant_id, User.username == username)
            ).scalar_one_or_none()
            if user is None:
                raise NotFound(f"user '{username}' does not exist")
            changed: dict[str, Any] = {}
            if roles is not None and roles != list(user.roles or []):
                user.roles = roles
                changed["roles"] = roles
            if disabled is not None and disabled != user.disabled:
                user.disabled = disabled
                changed["disabled"] = disabled
            if password_hash is not None:
                user.password_hash = password_hash
                user.failed_attempts = 0
                user.locked_until = None
                changed["password"] = "changed"
            if changed:
                audit.record(
                    session, tenant_id, actor=actor, action="user.update", target=f"user:{username}", detail=changed
                )
            return {"username": user.username, "roles": user.roles, "disabled": user.disabled, "tenant": tenant_id}

        return self.db.run(_work)

    def list_users(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.db.transaction() as session:
            rows = session.execute(select(User).where(User.tenant_id == tenant_id).order_by(User.username)).scalars()
            return [
                {
                    "username": u.username,
                    "roles": u.roles,
                    "disabled": u.disabled,
                    "locked": bool(u.locked_until and u.locked_until > utcnow()),
                    "created_at": u.created_at.isoformat(),
                    "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                }
                for u in rows
            ]

"""Application factory."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from importlib import resources
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secgraph import __version__
from secgraph.api.routes import admin, agents, analytics, graph, ingest, system
from secgraph.config import Settings, get_settings
from secgraph.context import AppContext, build_context
from secgraph.errors import SecGraphError
from secgraph.observability import (
    HTTP_LATENCY,
    HTTP_REQUESTS,
    configure_logging,
    get_logger,
    principal_var,
    request_id_var,
    tenant_var,
)

log = get_logger("secgraph.api")

_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
_DESCRIPTION = """
One graph of assets, identities, software, exposure, controls, detections, business services and AI agents —
with explainable attack-path mathematics and a governed interface for analysts and agents.

Authenticate with `Authorization: Bearer <token>` (from `POST /api/v1/auth/token`) or `X-API-Key: <key>`.
Errors have the shape `{"error": {"code", "message", "detail", "request_id"}}`.
"""


class BodyLimitMiddleware:
    """Reject request bodies above a byte limit, whether or not Content-Length is honest."""

    def __init__(self, app: ASGIApp, limit: int):
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            await self._reject(send)
            return
        received = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.limit:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        started = False

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if too_large and not started:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if too_large and not started:
            await self._reject(send)

    async def _reject(self, send: Send) -> None:
        body = (
            b'{"error":{"code":"limit_exceeded","message":"request body is larger than the configured limit",'
            b'"detail":{},"request_id":"-"}}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _error(status: int, code: str, message: str, detail: dict[str, Any] | None = None) -> JSONResponse:
    headers = {}
    if status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    if status == 429 and detail and "retry_after_seconds" in detail:
        headers["Retry-After"] = str(detail["retry_after_seconds"])
    return JSONResponse(
        {"error": {"code": code, "message": message, "detail": detail or {}, "request_id": request_id_var.get()}},
        status_code=status,
        headers=headers,
    )


def create_app(settings: Settings | None = None, *, context: AppContext | None = None) -> FastAPI:
    settings = settings or (context.settings if context else get_settings())
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ctx = context or build_context(settings)
        if settings.auto_migrate:
            from secgraph.store.migrate import upgrade

            upgrade(settings)
        ctx.auth.bootstrap()
        app.state.ctx = ctx
        log.info(
            "started",
            version=__version__,
            environment=settings.environment,
            dialect=ctx.db.dialect,
            ontology=f"{ctx.ontology.name} {ctx.ontology.version}",
        )
        try:
            yield
        finally:
            if context is None:
                ctx.close()

    app = FastAPI(
        title="Security Graph",
        version=__version__,
        description=_DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.add_middleware(BodyLimitMiddleware, limit=settings.ingest_max_body_bytes)
    origins = settings.cors_origin_list()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "X-API-Key", "X-Tenant-ID", "Content-Type", "MCP-Protocol-Version"],
            max_age=600,
        )

    @app.middleware("http")
    async def observe(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if 8 <= len(supplied) <= 64 and supplied.replace("-", "").isalnum() else uuid.uuid4().hex
        tokens = (request_id_var.set(request_id), tenant_var.set("-"), principal_var.set("-"))
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            template = getattr(route, "path", None) or (
                "/assets" if request.url.path.startswith("/assets") else "other"
            )
            HTTP_REQUESTS.labels(method=request.method, route=template, status=str(status)).inc()
            HTTP_LATENCY.labels(method=request.method, route=template).observe(elapsed)
            if template not in ("/health", "/ready", "/metrics", "/assets"):
                principal = getattr(request.state, "principal", None)
                log.info(
                    "request",
                    method=request.method,
                    path=request.url.path,
                    status=status,
                    duration_ms=round(elapsed * 1000, 1),
                    principal=principal.id if principal else "-",
                    tenant=principal.tenant_id if principal else "-",
                    client=request.client.host if request.client else "-",
                )
            request_id_var.reset(tokens[0])
            tenant_var.reset(tokens[1])
            principal_var.reset(tokens[2])
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        path = request.url.path
        if not path.startswith(("/docs", "/openapi.json")):
            response.headers["Content-Security-Policy"] = _CSP
        if path.startswith(("/api/", "/mcp")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(SecGraphError)
    async def handle_known(_request: Request, exc: SecGraphError) -> JSONResponse:
        if exc.status >= 500:
            log.error("request failed", code=exc.code, error=exc.message)
        return _error(exc.status, exc.code, exc.message, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            {"field": ".".join(str(p) for p in error["loc"] if p != "body"), "problem": error["msg"]}
            for error in exc.errors()[:20]
        ]
        return _error(422, "validation_failed", "the request is not valid", {"problems": problems})

    @app.exception_handler(StarletteHTTPException)
    async def handle_http(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed", 413: "limit_exceeded"}
        return _error(exc.status_code, codes.get(exc.status_code, "http_error"), str(exc.detail))

    @app.exception_handler(Exception)
    async def handle_unexpected(_request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error", exc_info=(type(exc), exc, exc.__traceback__))
        return _error(500, "internal_error", "an internal error occurred; quote the request id when reporting it")

    for module in (system, graph, ingest, analytics, agents, admin):
        app.include_router(module.router)

    # ---- operator console (static, no external assets) ---------------------
    static = resources.files("secgraph").joinpath("static")
    media_types = {
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
        ".json": "application/json",
    }

    def _asset(name: str) -> Response:
        if "/" in name or "\\" in name or name.startswith("."):
            return _error(404, "not_found", "no such asset")
        file = static.joinpath(name)
        suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if suffix not in media_types or not file.is_file():
            return _error(404, "not_found", "no such asset")
        return FileResponse(str(file), media_type=media_types[suffix], headers={"Cache-Control": "no-cache"})

    @app.get("/", include_in_schema=False)
    def console() -> Response:
        return _asset("index.html")

    @app.get("/assets/{name}", include_in_schema=False)
    def asset(name: str) -> Response:
        return _asset(name)

    return app


def app_factory() -> FastAPI:
    """Entry point for ``uvicorn --factory secgraph.api.app:app_factory``."""
    return create_app()

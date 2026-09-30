"""Python client for the Security Graph API.

    from secgraph.client import SecurityGraphClient

    graph = SecurityGraphClient("https://graph.soc.local", api_key=os.environ["SECGRAPH_API_KEY"])
    asset = graph.lookup("web-01.corp.example", type="Asset", kind="fqdn")[0]
    print(graph.context(asset["id"])["text"])

The client only needs ``httpx``; it does not import the server.

Reads (``GET``) are retried on connection failures and on 429, 502, 503 and 504,
with backoff and honouring ``Retry-After``. Writes are never retried by the client:
ingestion is idempotent, so the caller can safely send a batch again, but that is
the caller's decision.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import httpx

_RETRY_STATUS = frozenset({429, 502, 503, 504})


class SecurityGraphError(Exception):
    """An error response from the API."""

    def __init__(
        self, status: int, code: str, message: str, detail: dict[str, Any] | None = None, request_id: str | None = None
    ):
        super().__init__(f"{code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail or {}
        self.request_id = request_id


class SecurityGraphClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        token: str | None = None,
        tenant: str | None = None,
        timeout: float = 60.0,
        verify: bool | str = True,
        retries: int = 2,
        transport: httpx.BaseTransport | None = None,
    ):
        self.retries = max(0, retries)
        headers = {"Accept": "application/json", "User-Agent": "security-graph-client/1"}
        if api_key:
            headers["X-API-Key"] = api_key
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        if tenant:
            headers["X-Tenant-ID"] = tenant
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, verify=verify, transport=transport
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> SecurityGraphClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        params = kwargs.get("params")
        if params:
            kwargs["params"] = {k: v for k, v in params.items() if v is not None}
        attempts = self.retries + 1 if method == "GET" else 1
        for attempt in range(1, attempts + 1):
            try:
                response = self._http.request(method, path, **kwargs)
            except httpx.TransportError:
                if attempt == attempts:
                    raise
                time.sleep(min(0.25 * 2 ** (attempt - 1), 5.0))
                continue
            if response.status_code in _RETRY_STATUS and attempt < attempts:
                try:
                    delay = float(response.headers.get("Retry-After", ""))
                except ValueError:
                    delay = 0.25 * 2 ** (attempt - 1)
                time.sleep(max(0.0, min(delay, 5.0)))
                continue
            break
        if response.status_code >= 400:
            try:
                error = response.json()["error"]
            except (ValueError, KeyError, TypeError):
                raise SecurityGraphError(response.status_code, "http_error", response.text[:300]) from None
            raise SecurityGraphError(
                response.status_code,
                error.get("code", "error"),
                error.get("message", ""),
                error.get("detail"),
                error.get("request_id"),
            )
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    @staticmethod
    def _csv(values: list[str] | None) -> str | None:
        return ",".join(values) if values else None

    # ---- session ----------------------------------------------------------
    def login(self, username: str, password: str) -> dict[str, Any]:
        result = self._request("POST", "/api/v1/auth/token", json={"username": username, "password": password})
        self._http.headers["Authorization"] = f"Bearer {result['access_token']}"
        self._http.headers.pop("X-API-Key", None)
        return result

    def whoami(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/auth/me")

    # ---- read -------------------------------------------------------------
    def get(self, node_id: str, *, as_of: str | None = None) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/nodes/{node_id}", params={"as_of": as_of})

    def lookup(self, value: str, *, type: str | None = None, kind: str | None = None) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/lookup", params={"value": value, "type": type, "kind": kind})["items"]

    def search(
        self,
        *,
        q: str | None = None,
        types: list[str] | None = None,
        where: dict[str, Any] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/api/v1/nodes",
            params={
                "q": q,
                "type": self._csv(types),
                "where": json.dumps(where) if where else None,
                "limit": limit,
                "offset": offset,
            },
        )

    def iter_search(self, *, page_size: int = 200, **filters: Any) -> Iterator[dict[str, Any]]:
        offset = 0
        while True:
            page = self.search(limit=page_size, offset=offset, **filters)
            yield from page["items"]
            offset += len(page["items"])
            if not page["items"] or offset >= page["total"]:
                return

    def neighbors(
        self,
        node_id: str,
        *,
        direction: str = "both",
        edge_types: list[str] | None = None,
        node_types: list[str] | None = None,
        limit: int | None = None,
        as_of: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/api/v1/nodes/{node_id}/neighbors",
            params={
                "direction": direction,
                "edge_type": self._csv(edge_types),
                "node_type": self._csv(node_types),
                "limit": limit,
                "as_of": as_of,
            },
        )

    def history(self, node_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/api/v1/nodes/{node_id}/history")["versions"]

    def subgraph(self, seeds: list[str], *, depth: int = 1, **options: Any) -> dict[str, Any]:
        return self._request("POST", "/api/v1/query/subgraph", json={"seeds": seeds, "depth": depth, **options})

    def shortest_path(self, source_id: str, target_id: str, **options: Any) -> dict[str, Any]:
        return self._request(
            "POST", "/api/v1/query/path", json={"source_id": source_id, "target_id": target_id, **options}
        )

    def match(self, pattern: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/query/match", json={"pattern": pattern})

    def stats(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/stats")

    # ---- write ------------------------------------------------------------
    def ingest(
        self,
        source: str,
        nodes: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
        *,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"source": source, "nodes": nodes or [], "edges": edges or []}
        if observed_at:
            body["observed_at"] = observed_at
        return self._request("POST", "/api/v1/ingest", json=body)

    def ingest_source(
        self, mapping: str, payload: bytes | str, *, params: dict[str, str] | None = None, source: str | None = None
    ) -> dict[str, Any]:
        query: dict[str, Any] = {f"param.{k}": v for k, v in (params or {}).items()}
        query["source"] = source
        content = payload.encode() if isinstance(payload, str) else payload
        return self._request(
            "POST",
            f"/api/v1/ingest/source/{mapping}",
            content=content,
            params=query,
            headers={"Content-Type": "application/octet-stream"},
        )

    # ---- analytics --------------------------------------------------------
    def overview(self, **options: Any) -> dict[str, Any]:
        return self._request("GET", "/api/v1/analytics/overview", params=options)

    def attack_paths(
        self, *, target_id: str | None = None, source_id: str | None = None, k: int = 5, limit: int = 10
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/api/v1/analytics/attack-paths",
            params={"target_id": target_id, "source_id": source_id, "k": k, "limit": limit},
        )

    def exposure(self, node_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/analytics/nodes/{node_id}/exposure")

    def blast_radius(self, node_id: str, **options: Any) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/analytics/nodes/{node_id}/blast-radius", params=options)

    def remediation_priorities(self, *, by: str = "finding", limit: int = 20) -> dict[str, Any]:
        return self._request("GET", "/api/v1/analytics/remediation-priorities", params={"by": by, "limit": limit})

    def choke_points(self, *, limit: int = 10) -> dict[str, Any]:
        return self._request("GET", "/api/v1/analytics/choke-points", params={"limit": limit})

    def detection_race(self, *, target_id: str | None = None) -> dict[str, Any]:
        return self._request("GET", "/api/v1/analytics/detection-race", params={"target_id": target_id})

    # ---- agents -----------------------------------------------------------
    def context(self, node_id: str, *, budget_tokens: int | None = None) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/context/{node_id}", params={"budget_tokens": budget_tokens})

    def remember(
        self,
        kind: str,
        title: str,
        body: str = "",
        *,
        entity_ids: list[str] | None = None,
        tags: list[str] | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/memory",
            json={
                "kind": kind,
                "title": title,
                "body": body,
                "entity_ids": entity_ids or [],
                "tags": tags or [],
                **options,
            },
        )

    def recall(
        self, *, q: str | None = None, entity_id: str | None = None, kind: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        return self._request(
            "GET", "/api/v1/memory", params={"q": q, "entity_id": entity_id, "kind": kind, "limit": limit}
        )["items"]

    def suggest(
        self,
        *,
        entity_ids: list[str] | None = None,
        signature: list[str] | None = None,
        text: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        return self._request(
            "POST",
            "/api/v1/memory/suggest",
            json={"entity_ids": entity_ids or [], "signature": signature or [], "text": text, "limit": limit},
        )["items"]

    def feedback(self, note_id: str, outcome: str) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/memory/{note_id}/feedback", json={"outcome": outcome})

    # ---- change feed ------------------------------------------------------
    def changes(
        self, *, after: int = 0, limit: int = 500, kinds: list[str] | None = None, entity_types: list[str] | None = None
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/api/v1/changes",
            params={"after": after, "limit": limit, "kind": self._csv(kinds), "entity_type": self._csv(entity_types)},
        )

    def iter_changes(self, *, after: int = 0, **filters: Any) -> Iterator[dict[str, Any]]:
        """Every change after ``after``, in order. Persist the last ``seq`` you processed and resume from it."""
        cursor = after
        while True:
            page = self.changes(after=cursor, **filters)
            yield from page["items"]
            if page["cursor"] == cursor:
                return
            cursor = page["cursor"]

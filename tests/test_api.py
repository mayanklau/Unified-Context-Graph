"""The HTTP API end to end: authentication, authorisation, every route family, error handling."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from secgraph.demo.loader import read_source, seed_demo
from secgraph.governance.rbac import Principal


@pytest.fixture()
def demo(ctx, tenant):
    principal = Principal.build(id="user:test", name="test", kind="user", tenant_id=tenant, roles=["platform_admin"])
    return seed_demo(ctx, tenant, principal)


def find(client, headers, value, node_type=None, kind=None):
    params = {"value": value}
    if node_type:
        params.update(type=node_type, kind=kind)
    items = client.get("/api/v1/lookup", params=params, headers=headers).json()["items"]
    assert len(items) == 1, f"{value}: {len(items)} matches"
    return items[0]


# ---- system -----------------------------------------------------------------
def test_health_ready_and_security_headers(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert len(r.headers["x-request-id"]) >= 8
    ready = client.get("/ready").json()
    assert ready["status"] == "ready" and ready["ontology"]["version"] == "1.0.0"
    echoed = client.get("/health", headers={"X-Request-ID": "trace-1234567890"})
    assert echoed.headers["x-request-id"] == "trace-1234567890"
    assert client.get("/").status_code == 200
    assert client.get("/assets/..%2f..%2fconfig.py").status_code == 404
    assert client.get("/assets/.env").status_code == 404


def test_metrics_exposes_graph_gauges(client, demo, tenant):
    text = client.get("/metrics").text
    assert f'secgraph_nodes{{tenant="{tenant}",type="Asset"}} 16.0' in text
    assert "secgraph_http_requests_total" in text and "secgraph_ingest_records_total" in text


def test_errors_have_one_shape(client, auth):
    r = client.get("/api/v1/nodes")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    body = r.json()["error"]
    assert body["code"] == "unauthenticated" and body["request_id"] == r.headers["x-request-id"]
    assert client.get("/api/v1/nope", headers=auth("viewer")).json()["error"]["code"] == "not_found"
    r = client.get("/api/v1/nodes", params={"limit": 0}, headers=auth("viewer"))
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_failed"
    r = client.get("/api/v1/nodes", params={"where": "{bad json"}, headers=auth("viewer"))
    assert r.status_code == 422 and "must be JSON" in r.json()["error"]["message"]
    r = client.post("/api/v1/query/path", json={"source_id": "a"}, headers=auth("viewer"))
    assert r.status_code == 422 and r.json()["error"]["detail"]["problems"][0]["field"] == "target_id"
    r = client.get("/api/v1/nodes/" + "0" * 32, headers=auth("viewer"))
    assert r.status_code == 404
    assert client.delete("/api/v1/nodes", headers=auth("viewer")).status_code == 405


# ---- authentication ---------------------------------------------------------
def test_password_login_lockout_and_disable(client, ctx, tenant):
    username = f"asha-{uuid.uuid4().hex[:8]}"
    ctx.auth.create_user(tenant, "user:test", username=username, password="Correct-Horse-9", roles=["analyst"])
    bad = client.post("/api/v1/auth/token", json={"username": username, "password": "wrong"})
    assert bad.status_code == 401 and bad.json()["error"]["message"] == "invalid credentials"
    unknown = client.post("/api/v1/auth/token", json={"username": "nobody-" + username, "password": "x"})
    assert unknown.json()["error"]["message"] == "invalid credentials"  # indistinguishable from a wrong password
    token = client.post("/api/v1/auth/token", json={"username": username.upper(), "password": "Correct-Horse-9"})
    assert token.status_code == 200
    bearer = {"Authorization": f"Bearer {token.json()['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=bearer).json()
    assert me["tenant"] == tenant and me["roles"] == ["analyst"] and "analytics:read" in me["permissions"]
    # disabling takes effect on the very next request, not at token expiry
    ctx.auth.update_user(tenant, "user:test", username, disabled=True)
    assert client.get("/api/v1/auth/me", headers=bearer).status_code == 401
    ctx.auth.update_user(tenant, "user:test", username, disabled=False)
    for _ in range(ctx.settings.login_max_failures):
        client.post("/api/v1/auth/token", json={"username": username, "password": "wrong"})
    locked = client.post("/api/v1/auth/token", json={"username": username, "password": "Correct-Horse-9"})
    assert locked.status_code in (401, 429)  # locked out even with the right password


def test_tokens_cannot_be_forged(client, ctx, tenant):
    import jwt

    forged = jwt.encode(
        {
            "iss": ctx.settings.jwt_issuer,
            "sub": "user:admin",
            "tenant": tenant,
            "roles": ["admin"],
            "iat": 1,
            "exp": 9999999999,
        },
        "not-the-secret-not-the-secret-0000",
        algorithm="HS256",
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    unsigned = jwt.encode({"sub": "user:admin", "exp": 9999999999}, None, algorithm="none")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {unsigned}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"X-API-Key": "sg_000000000000_" + "a" * 43}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"X-API-Key": "garbage"}).status_code == 401


def test_weak_passwords_and_unknown_roles_are_refused(client, auth):
    admin = auth("admin")
    weak = client.post(
        "/api/v1/users", json={"username": "weak-user", "password": "short", "roles": ["viewer"]}, headers=admin
    )
    assert weak.status_code == 422 and "at least 12" in weak.json()["error"]["message"]
    role = client.post(
        "/api/v1/users", json={"username": "x-user", "password": "Correct-Horse-9", "roles": ["god"]}, headers=admin
    )
    assert role.status_code == 422 and "unknown role" in role.json()["error"]["message"]
    escalate = client.post(
        "/api/v1/users",
        json={"username": "y-user", "password": "Correct-Horse-9", "roles": ["platform_admin"]},
        headers=admin,
    )
    assert escalate.status_code == 422  # a tenant admin cannot mint a platform admin


def test_api_key_lifecycle(client, auth):
    admin = auth("admin")
    created = client.post(
        "/api/v1/api-keys",
        json={"name": "triage agent", "roles": ["agent"], "kind": "agent", "expires_in_days": 30},
        headers=admin,
    )
    assert created.status_code == 201
    key = created.json()
    assert key["api_key"].startswith("sg_") and key["expires_at"]
    listed = client.get("/api/v1/api-keys", headers=admin).json()["items"]
    mine = next(k for k in listed if k["id"] == key["id"])
    assert "api_key" not in mine and "key_hash" not in mine and mine["prefix"].endswith("…")
    headers = {"Authorization": f"Bearer {key['api_key']}"}  # keys also work as bearer credentials
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["kind"] == "agent" and "pii:read" not in me["permissions"]
    assert client.delete(f"/api/v1/api-keys/{key['id']}", headers=admin).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    bad = client.post("/api/v1/api-keys", json={"name": "x", "roles": ["platform_admin"]}, headers=admin)
    assert bad.status_code == 422


# ---- authorisation ----------------------------------------------------------
@pytest.mark.parametrize(
    "role, allowed, denied",
    [
        (
            "viewer",
            ["/api/v1/nodes", "/api/v1/stats"],
            [
                "/api/v1/analytics/overview",
                "/api/v1/audit",
                "/api/v1/memory",
                "/api/v1/users",
                "/api/v1/quarantine",
                "/api/v1/changes",
            ],
        ),
        (
            "agent",
            ["/api/v1/nodes", "/api/v1/analytics/overview", "/api/v1/memory"],
            ["/api/v1/audit", "/api/v1/users", "/api/v1/api-keys", "/api/v1/quarantine"],
        ),
        ("ingest", ["/api/v1/ingest/mappings"], ["/api/v1/nodes", "/api/v1/analytics/overview", "/api/v1/audit"]),
        ("auditor", ["/api/v1/audit", "/api/v1/audit/verify", "/api/v1/changes"], ["/api/v1/users", "/api/v1/memory"]),
    ],
)
def test_roles_limit_what_can_be_called(client, auth, role, allowed, denied):
    headers = auth(role)
    for path in allowed:
        assert client.get(path, headers=headers).status_code == 200, path
    for path in denied:
        r = client.get(path, headers=headers)
        assert r.status_code == 403 and r.json()["error"]["code"] == "permission_denied", path
    if role != "ingest":
        assert client.post("/api/v1/ingest", json={"source": "x"}, headers=headers).status_code == 403


def test_type_restricted_key_sees_only_its_types_and_no_analytics(client, auth, demo):
    headers = auth("agent", node_types=["Asset", "Finding", "Vulnerability"])
    stats = client.get("/api/v1/stats", headers=headers).json()
    assert set(stats["nodes"]) == {"Asset", "Finding", "Vulnerability"}
    assert client.get("/api/v1/nodes", params={"type": "Identity"}, headers=headers).json()["total"] == 0
    r = client.get("/api/v1/analytics/overview", headers=headers)
    assert r.status_code == 403 and "restricted" in r.json()["error"]["message"]
    full = auth("analyst")
    identity = find(client, full, "corp\\asharma", "Identity", "account")
    assert client.get(f"/api/v1/nodes/{identity['id']}", headers=headers).status_code == 404


def test_tenant_isolation_and_platform_admin_override(client, ctx, auth, demo, tenant):
    other = "t-" + uuid.uuid4().hex[:10]
    other_key = ctx.auth.create_api_key(other, "user:test", name="other", roles=["admin"])["api_key"]
    other_headers = {"X-API-Key": other_key}
    assert client.get("/api/v1/stats", headers=other_headers).json()["node_total"] == 0
    web = find(client, auth("analyst"), "web-portal-01.dmz.meridian.example", "Asset", "fqdn")
    assert client.get(f"/api/v1/nodes/{web['id']}", headers=other_headers).status_code == 404
    # a tenant admin cannot hop tenants with a header
    hop = client.get("/api/v1/stats", headers={**other_headers, "X-Tenant-ID": tenant})
    assert hop.status_code == 403
    # a platform admin (a user; keys cannot hold the role) can
    username = f"root-{uuid.uuid4().hex[:8]}"
    ctx.auth.create_user(
        other,
        "user:test",
        username=username,
        password="Correct-Horse-9",
        roles=["platform_admin"],
        allow_platform_admin=True,
    )
    token = client.post("/api/v1/auth/token", json={"username": username, "password": "Correct-Horse-9"}).json()
    bearer = {"Authorization": f"Bearer {token['access_token']}"}
    assert client.get("/api/v1/stats", headers=bearer).json()["node_total"] == 0
    assert client.get("/api/v1/stats", headers={**bearer, "X-Tenant-ID": tenant}).json()["node_total"] == 110


# ---- graph ------------------------------------------------------------------
def test_ingest_and_read_back(client, auth):
    writer, reader = auth("ingest"), auth("analyst")
    batch = {
        "source": "api-test",
        "nodes": [
            {
                "type": "Asset",
                "identifiers": {"fqdn": "api-01.corp.example"},
                "properties": {"criticality": 4},
                "ref": "a",
            },
            {"type": "Asset", "identifiers": {"fqdn": "api-02.corp.example"}, "ref": "b"},
            {"type": "Asset", "identifiers": {"fqdn": "bad"}},
        ],
        "edges": [{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "b"}, "properties": {"port": 443}}],
    }
    r = client.post("/api/v1/ingest", json=batch, headers=writer)
    assert r.status_code == 200
    out = r.json()
    assert out["nodes"]["created"] == 2 and out["edges"]["created"] == 1 and out["quarantined_total"] == 1
    assert "fully qualified" in out["quarantined"][0]["reason"]
    node_id = out["refs"]["a"]
    node = client.get(f"/api/v1/nodes/{node_id}", headers=reader).json()
    assert node["name"] == "api-01" and node["degree"] == {"CONNECTS_TO": {"out": 1, "in": 0}}
    around = client.get(f"/api/v1/nodes/{node_id}/neighbors", params={"direction": "out"}, headers=reader).json()
    assert around["neighbors"][0]["node"]["name"] == "api-02"
    edge_id = around["neighbors"][0]["edge"]["id"]
    edge = client.get(f"/api/v1/edges/{edge_id}", headers=reader).json()
    assert edge["current"] is True and edge["edge"]["properties"] == {"port": 443} and len(edge["versions"]) == 1
    search = client.get(
        "/api/v1/nodes", params={"type": "Asset", "where": json.dumps({"criticality": {"gte": 4}})}, headers=reader
    ).json()
    assert [n["id"] for n in search["items"]] == [node_id]
    batches = client.get("/api/v1/ingest/batches", headers=writer).json()["items"]
    assert batches[0]["status"] == "completed" and batches[0]["counts"]["quarantined"] == 1
    bad = client.post("/api/v1/ingest", json={"source": "BAD SOURCE", "nodes": []}, headers=writer)
    assert bad.status_code == 422
    extra = client.post("/api/v1/ingest", json={"source": "x", "nodes": [], "bogus": 1}, headers=writer)
    assert extra.status_code == 422


def test_ingest_source_file_through_a_mapping(client, auth):
    writer, reader = auth("ingest"), auth("viewer")
    mappings = client.get("/api/v1/ingest/mappings", headers=writer).json()["items"]
    assert {m["name"] for m in mappings} >= {"assets_csv", "nvd_cve"}
    r = client.post(
        "/api/v1/ingest/source/assets_csv",
        content=read_source("assets.csv"),
        headers={**writer, "Content-Type": "text/csv"},
    )
    assert r.status_code == 200 and r.json()["nodes"]["created"] == 25
    r = client.post(
        "/api/v1/ingest/source/cyclonedx",
        content=read_source("web-portal-01.cdx.json"),
        params={"param.asset_fqdn": "web-portal-01.dmz.meridian.example", "source": "sbom-ci"},
        headers=writer,
    )
    assert r.status_code == 200 and r.json()["source"] == "sbom-ci" and r.json()["edges"]["created"] == 5
    assert client.get("/api/v1/stats", headers=reader).json()["nodes"]["Software"] == 5
    assert client.post("/api/v1/ingest/source/nope", content="x", headers=writer).status_code == 404
    assert client.post("/api/v1/ingest/source/assets_csv", content="", headers=writer).status_code == 422
    r = client.post("/api/v1/ingest/source/cyclonedx", content="{}", params={"param.bogus": "1"}, headers=writer)
    assert r.status_code == 422


def test_queries_over_http(client, auth, demo):
    h = auth("analyst")
    web = find(client, h, "web-portal-01.dmz.meridian.example", "Asset", "fqdn")
    cve = find(client, h, "CVE-2021-44228", "Vulnerability", "cve")
    path = client.post("/api/v1/query/path", json={"source_id": web["id"], "target_id": cve["id"]}, headers=h).json()
    assert path["found"] and path["length"] == 2
    sub = client.post("/api/v1/query/subgraph", json={"seeds": [web["id"]], "depth": 1}, headers=h).json()
    assert len(sub["nodes"]) > 5 and not sub["truncated"]
    match = client.post(
        "/api/v1/query/match",
        json={
            "pattern": {
                "start": {"type": "Asset", "where": {"internet_exposed": True}},
                "steps": [
                    {"edge": "HAS_FINDING", "node": {"type": "Finding", "where": {"status": {"in": ["open"]}}}},
                    {"edge": "INSTANCE_OF", "node": {"type": "Vulnerability", "where": {"kev": True}}},
                ],
            }
        },
        headers=h,
    ).json()
    names = sorted({m["nodes"][0]["name"] for m in match["matches"]})
    assert names == ["api-gw-01", "web-portal-01", "wiki-01"]  # the VPN finding is risk-accepted, not open
    history = client.get(f"/api/v1/nodes/{cve['id']}/history", headers=h).json()["versions"]
    assert [v["changed_by"] for v in history] == ["epss", "kev", "nvd"]
    assert client.get("/api/v1/ontology", headers=h).json()["ontology"]["name"] == "security-graph-core"
    as_of = client.get(f"/api/v1/nodes/{web['id']}", params={"as_of": "2020-01-01T00:00:00Z"}, headers=h)
    assert as_of.status_code == 404
    future = client.get(f"/api/v1/nodes/{web['id']}", params={"as_of": "2999-01-01"}, headers=h)
    assert future.status_code == 422


# ---- analytics, context, memory --------------------------------------------
def test_analytics_over_http(client, auth, demo):
    h = auth("analyst")
    overview = client.get("/api/v1/analytics/overview", headers=h).json()
    assert overview["entry_points"] == 4 and overview["targets"] == 15
    assert overview["risk"]["lower"] <= overview["risk"]["estimate"] <= overview["risk"]["upper"]
    dc = find(client, h, "ad-dc-01.core.meridian.example", "Asset", "fqdn")
    paths = client.get("/api/v1/analytics/attack-paths", params={"target_id": dc["id"], "k": 3}, headers=h).json()
    assert len(paths["paths"]) == 3
    probabilities = [p["probability"] for p in paths["paths"]]
    assert probabilities == sorted(probabilities, reverse=True)
    assert paths["paths"][0]["steps"][-1]["basis"]["findings"][0]["vulnerability"] == "CVE-2020-1472"
    exposure = client.get(f"/api/v1/analytics/nodes/{dc['id']}/exposure", headers=h).json()
    assert exposure["node"]["impact"] == 16 and exposure["open_finding_count"] == 1
    assert exposure["detection_per_attempt"] > 0.02  # EDR and SIEM detections cover the domain controller
    blast = client.get(f"/api/v1/analytics/nodes/{dc['id']}/blast-radius", headers=h).json()
    assert "Core Banking" in {s["name"] for s in blast["business_services"]}
    priorities = client.get(
        "/api/v1/analytics/remediation-priorities", params={"by": "vulnerability"}, headers=h
    ).json()
    assert priorities["items"] and priorities["items"][0]["risk_reduction"] > 0
    reductions = [i["risk_reduction"] for i in priorities["items"]]
    assert reductions == sorted(reductions, reverse=True)
    chokes = client.get("/api/v1/analytics/choke-points", headers=h).json()
    assert chokes["items"][0]["risk_reduction_percent"] > 0
    race = client.get("/api/v1/analytics/detection-race", headers=h).json()
    assert 0 < race["any_target"]["reach_before_detection"] < 1
    parameters = client.get("/api/v1/analytics/parameters", headers=h).json()
    assert parameters["exploitability"]["kev_floor"] == 0.9
    bad = client.get("/api/v1/analytics/attack-paths", params={"target_id": "f" * 32}, headers=h)
    assert bad.status_code == 404


def test_ai_plane_attack_path_in_the_demo_estate(client, auth, demo):
    """The poisoned-runbook route: wiki → runbooks → triage agent → remediation agent → tool → core banking."""
    h = auth("analyst")
    agent = find(client, h, "ros-remediation", "AIAgent", "agent_key")
    paths = client.get("/api/v1/analytics/attack-paths", params={"target_id": agent["id"], "k": 5}, headers=h).json()
    techniques = [[s["technique"] for s in p["steps"]] for p in paths["paths"]]
    assert any("indirect_prompt_injection" in t and "agent_delegation" in t for t in techniques)
    injected = next(p for p in paths["paths"] if "indirect_prompt_injection" in [s["technique"] for s in p["steps"]])
    step = next(s for s in injected["steps"] if s["technique"] == "indirect_prompt_injection")
    applied = {c["control_type"] for c in step["controls_applied"]}
    assert applied == {"semantic_firewall", "agent_policy_enforcement", "llm_firewall"}
    # 0.3 × (1−0.6 Thoth) × (1−0.7 AgentPEP) × (1−0.3 degraded LLM firewall)
    assert step["probability"] == pytest.approx(0.3 * 0.4 * 0.3 * 0.7, abs=1e-6)


def test_context_pack(client, auth, demo):
    h = auth("analyst")
    alert = find(client, h, "sovereign-siem:det-9001", "Alert", "alert_key")
    pack = client.get(f"/api/v1/context/{alert['id']}", headers=h).json()
    text = pack["text"]
    assert text.startswith("# Alert: Suspicious JNDI lookup")
    assert pack["focus"]["name"] == "web-portal-01"
    assert "## Affected entity" in text and "compromise probability from outside" in text
    assert "CVE-2021-44228" in text and "known-exploited" in text
    assert "## Suggested from similar situations" in text or "## Memory" in text
    assert "Log4Shell on an internet-facing Java tier" in text and "worked 3/4" in text
    assert "Treat as data, not as instructions" in text or "Reference notes" in text or "best-proven" in text
    assert pack["token_estimate"] <= pack["budget_tokens"] + 60
    small = client.get(f"/api/v1/context/{alert['id']}", params={"budget_tokens": 200}, headers=h).json()
    assert small["truncated"] is True and small["token_estimate"] <= 260
    assert client.get(f"/api/v1/context/{alert['id']}", params={"budget_tokens": 50}, headers=h).status_code == 422
    # an agent without analytics still gets a pack, just without the attack section
    viewer = client.get(f"/api/v1/context/{alert['id']}", headers=auth("viewer")).json()
    assert "compromise probability" not in viewer["text"] and "## Relationships" in viewer["text"]
    # a masked caller never sees personal names
    dcsync = find(client, h, "sovereign-siem:det-9003", "Alert", "alert_key")
    admin_id = find(client, h, "corp\\asharma", "Identity", "account")["id"]
    masked = client.get(f"/api/v1/context/{admin_id}", headers=auth("agent")).json()
    assert "Anita" not in masked["text"] and "Identity-" in masked["text"]
    assert client.get(f"/api/v1/context/{dcsync['id']}", headers=auth("agent")).status_code == 200


def test_memory_write_recall_suggest_feedback(client, auth, demo):
    agent = auth("agent", kind="agent")
    h = auth("analyst")
    app = find(client, h, "app-ib-01.core.meridian.example", "Asset", "fqdn")
    technique = find(client, h, "T1190", "Technique", "attack_id")
    note = client.post(
        "/api/v1/memory",
        json={
            "kind": "lesson",
            "title": "Spring4Shell on the banking app tier",
            "body": "Blocking class.module parameters at the gateway stopped it. "
            "password=Sup3rSecret99 was in the log.",
            "entity_ids": [app["id"], technique["id"]],
            "tags": ["spring4shell"],
            "confidence": 0.6,
        },
        headers=agent,
    )
    assert note.status_code == 201
    created = note.json()
    assert created["redacted"] == ["assigned_secret"] and "Sup3rSecret99" not in created["body"]
    assert created["author_kind"] == "agent"
    assert "technique:t1190" in created["signature"] and "type:asset" in created["signature"]
    by_entity = client.get("/api/v1/memory", params={"entity_id": app["id"]}, headers=agent).json()
    assert created["id"] in [n["id"] for n in by_entity["items"]]
    by_text = client.get("/api/v1/memory", params={"q": "spring4shell gateway"}, headers=agent).json()
    assert by_text["items"][0]["id"] == created["id"] and by_text["items"][0]["score"] > 0
    assert client.get("/api/v1/memory", params={"q": "zzzunrelatedzzz"}, headers=agent).json()["total"] == 0
    # a similar situation elsewhere: another internet-facing exploitation case pulls the proven lesson first
    web = find(client, h, "web-portal-01.dmz.meridian.example", "Asset", "fqdn")
    suggested = client.post(
        "/api/v1/memory/suggest", json={"entity_ids": [web["id"], technique["id"]]}, headers=agent
    ).json()["items"]
    assert suggested[0]["title"].startswith("Log4Shell on an internet-facing Java tier")  # 3 of 4 successes
    assert created["id"] in [s["id"] for s in suggested]
    before = next(s for s in suggested if s["id"] == created["id"])["score"]
    for _ in range(3):
        fb = client.post(f"/api/v1/memory/{created['id']}/feedback", json={"outcome": "success"}, headers=agent)
        assert fb.status_code == 200
    after = client.post(
        "/api/v1/memory/suggest", json={"entity_ids": [web["id"], technique["id"]]}, headers=agent
    ).json()["items"]
    assert next(s for s in after if s["id"] == created["id"])["score"] > before
    assert client.delete(f"/api/v1/memory/{created['id']}", headers=agent).status_code == 204
    assert created["id"] not in [
        n["id"] for n in client.get("/api/v1/memory", params={"entity_id": app["id"]}, headers=agent).json()["items"]
    ]
    bad = client.post("/api/v1/memory", json={"kind": "rumour", "title": "nope"}, headers=agent)
    assert bad.status_code == 422
    missing = client.post(
        "/api/v1/memory", json={"kind": "lesson", "title": "orphan note", "entity_ids": ["0" * 32]}, headers=agent
    )
    assert missing.status_code == 404


# ---- curation, changes, audit ----------------------------------------------
def test_quarantine_conflicts_and_merge_over_http(client, auth):
    writer, steward = auth("ingest"), auth("steward")
    out = client.post(
        "/api/v1/ingest",
        json={
            "source": "cmdb",
            "nodes": [
                {"type": "Asset", "identifiers": {"fqdn": "app.prod.example"}, "ref": "p"},
                {"type": "Asset", "identifiers": {"fqdn": "app.dev.example"}, "ref": "d"},
                {"type": "Control", "identifiers": {"control_key": "c-1"}},
            ],
        },
        headers=writer,
    ).json()
    client.post(
        "/api/v1/ingest",
        json={"source": "edr", "nodes": [{"type": "Asset", "identifiers": {"hostname": "app"}, "ref": "x"}]},
        headers=writer,
    )
    quarantine = client.get("/api/v1/quarantine", headers=steward).json()
    assert quarantine["total"] == 1 and "control_type" in quarantine["items"][0]["reason"]
    assert client.get("/api/v1/quarantine", headers=writer).status_code == 403
    discarded = client.post(
        "/api/v1/quarantine/discard", json={"ids": [quarantine["items"][0]["id"]]}, headers=steward
    ).json()
    assert discarded == {"discarded": 1}
    conflicts = client.get("/api/v1/conflicts", headers=steward).json()
    assert conflicts["total"] == 1 and conflicts["items"][0]["reason"] == "ambiguous_weak_match"
    lookup = client.get(
        "/api/v1/lookup", params={"value": "app", "type": "Asset", "kind": "hostname"}, headers=steward
    ).json()
    assert lookup["total"] == 3
    orphan = next(i for i in lookup["items"] if "fqdn" not in i["identifiers"])
    merged = client.post(
        "/api/v1/nodes/merge", json={"survivor_id": out["refs"]["p"], "duplicate_id": orphan["id"]}, headers=steward
    )
    assert merged.status_code == 200 and merged.json()["merged"] == orphan["id"]
    redirected = client.get(f"/api/v1/nodes/{orphan['id']}", headers=steward).json()
    assert redirected["id"] == out["refs"]["p"] and redirected["requested_id"] == orphan["id"]
    assert client.get("/api/v1/conflicts", headers=steward).json()["total"] == 0
    # the decision sticks: the next host-name-only record lands on the chosen node, with no new placeholder
    again = client.post(
        "/api/v1/ingest",
        json={"source": "edr", "nodes": [{"type": "Asset", "identifiers": {"hostname": "app"}, "ref": "x"}]},
        headers=writer,
    ).json()
    assert again["refs"]["x"] == out["refs"]["p"] and again["nodes"]["created"] == 0 and again["conflicts"] == 0
    assert redirected["identifiers"]["pin.hostname"] == ["app"]


def test_resolving_a_conflict_pins_the_decision(client, auth):
    writer, steward = auth("ingest"), auth("steward")
    out = client.post(
        "/api/v1/ingest",
        json={
            "source": "cmdb",
            "nodes": [
                {"type": "Asset", "identifiers": {"fqdn": "db.prod.example"}, "ref": "p"},
                {"type": "Asset", "identifiers": {"fqdn": "db.dev.example"}, "ref": "d"},
            ],
        },
        headers=writer,
    ).json()
    first = client.post(
        "/api/v1/ingest",
        json={"source": "scanner", "nodes": [{"type": "Asset", "identifiers": {"hostname": "db"}, "ref": "x"}]},
        headers=writer,
    ).json()
    assert first["conflicts"] == 1 and first["refs"]["x"] not in (out["refs"]["p"], out["refs"]["d"])
    conflict = client.get("/api/v1/conflicts", headers=steward).json()["items"][0]
    wrong = client.post(f"/api/v1/conflicts/{conflict['id']}/resolve", json={"node_id": "0" * 32}, headers=steward)
    assert wrong.status_code == 404
    resolved = client.post(
        f"/api/v1/conflicts/{conflict['id']}/resolve", json={"node_id": out["refs"]["d"]}, headers=steward
    ).json()
    assert resolved["merged"] == [first["refs"]["x"]]  # the placeholder is folded into the chosen node
    assert client.get("/api/v1/conflicts", headers=steward).json()["total"] == 0
    again = client.post(
        f"/api/v1/conflicts/{conflict['id']}/resolve", json={"node_id": out["refs"]["d"]}, headers=steward
    )
    assert again.status_code == 409
    later = client.post(
        "/api/v1/ingest",
        json={"source": "scanner", "nodes": [{"type": "Asset", "identifiers": {"hostname": "db"}, "ref": "x"}]},
        headers=writer,
    ).json()
    assert later["refs"]["x"] == out["refs"]["d"] and later["conflicts"] == 0
    assert client.get("/api/v1/stats", headers=steward).json()["nodes"]["Asset"] == 2


def test_change_feed_and_audit_chain(client, auth, ctx, tenant):
    writer, auditor = auth("ingest"), auth("auditor")
    client.post(
        "/api/v1/ingest",
        json={
            "source": "t",
            "nodes": [
                {"type": "Asset", "identifiers": {"fqdn": "c1.corp.example"}, "ref": "a"},
                {"type": "Asset", "identifiers": {"fqdn": "c2.corp.example"}, "ref": "b"},
            ],
            "edges": [{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "b"}}],
        },
        headers=writer,
    )
    feed = client.get("/api/v1/changes", headers=auditor).json()
    assert [e["kind"] for e in feed["items"]] == ["node.created", "node.created", "edge.created"]
    assert [e["seq"] for e in feed["items"]] == [1, 2, 3] and feed["cursor"] == 3 and feed["head"] == 3
    assert client.get("/api/v1/changes", params={"after": 3}, headers=auditor).json()["items"] == []
    only_edges = client.get("/api/v1/changes", params={"kind": "edge.created"}, headers=auditor).json()
    assert len(only_edges["items"]) == 1
    log = client.get("/api/v1/audit", headers=auditor).json()["items"]
    assert {"ingest.completed", "apikey.create"} <= {e["action"] for e in log}
    assert client.get("/api/v1/audit/verify", headers=auditor).json()["ok"] is True
    # tampering with any entry is detected
    from sqlalchemy import select

    from secgraph.store.models import AuditEntry

    with ctx.db.transaction() as s:
        entry = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant, AuditEntry.seq == 1)).scalar_one()
        entry.detail = {**entry.detail, "tampered": True}
    verdict = client.get("/api/v1/audit/verify", headers=auditor).json()
    assert verdict == {"ok": False, "entries": 0, "broken_at_seq": 1, "reason": "hash mismatch"}


def test_webhooks_deliver_signed_batches_and_back_off(client, auth, ctx, tenant):
    from secgraph.events.webhooks import WebhookService, sign

    admin, writer = auth("admin"), auth("ingest")
    bad = client.post("/api/v1/webhooks", json={"name": "meta", "url": "http://169.254.169.254/latest"}, headers=admin)
    assert bad.status_code == 422 and "link-local" in bad.json()["error"]["message"]
    assert (
        client.post("/api/v1/webhooks", json={"name": "f", "url": "file:///etc/passwd"}, headers=admin).status_code
        == 422
    )
    created = client.post(
        "/api/v1/webhooks",
        json={
            "name": "ros",
            "url": "http://127.0.0.1:9/hook",
            "event_kinds": ["node.created"],
            "entity_types": ["Finding"],
        },
        headers=admin,
    )
    assert created.status_code == 201
    hook = created.json()
    assert len(hook["secret"]) >= 32
    assert "secret" not in client.get("/api/v1/webhooks", headers=admin).json()["items"][0]
    client.post(
        "/api/v1/ingest",
        json={
            "source": "t",
            "nodes": [
                {"type": "Asset", "identifiers": {"fqdn": "w1.corp.example"}},
                {"type": "Finding", "identifiers": {"finding_key": "wf-1"}},
                {"type": "Finding", "identifiers": {"finding_key": "wf-2"}},
            ],
        },
        headers=writer,
    )

    received: list[httpx.Request] = []
    status = {"code": 500}

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(status["code"])

    service = WebhookService(ctx.db, ctx.settings, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert service.deliver_pending()["failed"] >= 1
    state = next(h for h in client.get("/api/v1/webhooks", headers=admin).json()["items"] if h["id"] == hook["id"])
    assert state["failures"] == 1 and state["last_error"] == "HTTP 500" and state["next_attempt_at"]
    assert service.deliver_pending()["delivered"] == 0  # backing off: not retried yet
    client.patch(f"/api/v1/webhooks/{hook['id']}", json={"active": True}, headers=admin)  # clears the back-off
    status["code"] = 204
    received.clear()
    assert service.deliver_pending()["delivered"] >= 1
    request = next(r for r in received if json.loads(r.content)["webhook_id"] == hook["id"])
    body = json.loads(request.content)
    assert [e["kind"] for e in body["events"]] == ["node.created", "node.created"]
    assert {e["entity_type"] for e in body["events"]} == {"Finding"} and body["gap"] is False
    assert request.headers["x-secgraph-signature"] == sign(
        hook["secret"], request.headers["x-secgraph-timestamp"], request.content
    )
    received.clear()
    service.deliver_pending()
    assert not [r for r in received if json.loads(r.content)["webhook_id"] == hook["id"]]  # nothing new: no resend
    assert client.delete(f"/api/v1/webhooks/{hook['id']}", headers=admin).status_code == 204


def test_vault_export(client, auth, demo):
    import io
    import tarfile

    r = client.get("/api/v1/export/vault", headers=auth("analyst"))
    assert r.status_code == 200 and r.headers["content-type"] == "application/gzip"
    with tarfile.open(fileobj=io.BytesIO(r.content)) as archive:
        names = archive.getnames()
        assert "security-graph-vault/CLAUDE.md" in names and "security-graph-vault/INDEX.md" in names
        assert "security-graph-vault/analytics/overview.md" in names
        page = next(n for n in names if n.startswith("security-graph-vault/Asset/web-portal-01-"))
        text = archive.extractfile(page).read().decode()
        assert "# Asset: web-portal-01" in text and "**HAS_FINDING** → [[Finding/" in text
        assert "## Memory" in text
        index = archive.extractfile("security-graph-vault/INDEX.md").read().decode()
        assert "| [[Asset/_index|Asset]] | 16 | 16 |" in index
        assert all(".." not in n for n in names)
    masked = client.get("/api/v1/export/vault", headers=auth("viewer"))
    with tarfile.open(fileobj=io.BytesIO(masked.content)) as archive:
        names = archive.getnames()
        assert "security-graph-vault/analytics/overview.md" not in names
        assert not any("anita" in n.lower() for n in names)


# ---- limits -----------------------------------------------------------------
def test_request_body_limit(ctx):
    from fastapi.testclient import TestClient

    from secgraph.api.app import create_app
    from secgraph.context import build_context
    from tests.conftest import make_settings

    settings = make_settings(ctx.settings.database_url, ingest_max_body_bytes=2000)
    with TestClient(create_app(context=build_context(settings, db=ctx.db))) as small:
        key = ctx.auth.create_api_key("limits", "user:test", name="w", roles=["ingest"])["api_key"]
        big = {
            "source": "t",
            "nodes": [{"type": "Asset", "identifiers": {"fqdn": f"h{i}.corp.example"}} for i in range(200)],
        }
        r = small.post("/api/v1/ingest", json=big, headers={"X-API-Key": key})
        assert r.status_code == 413 and r.json()["error"]["code"] == "limit_exceeded"
        ok = small.post("/api/v1/ingest", json={"source": "t", "nodes": []}, headers={"X-API-Key": key})
        assert ok.status_code == 200


def test_rate_limit(ctx):
    from fastapi.testclient import TestClient

    from secgraph.api.app import create_app
    from secgraph.context import build_context
    from tests.conftest import make_settings

    settings = make_settings(ctx.settings.database_url, rate_limit_per_minute=60, rate_limit_burst=5)
    with TestClient(create_app(context=build_context(settings, db=ctx.db))) as limited:
        key = ctx.auth.create_api_key("limits", "user:test", name="r", roles=["viewer"])["api_key"]
        codes = [limited.get("/api/v1/stats", headers={"X-API-Key": key}).status_code for _ in range(8)]
        assert codes[:5] == [200] * 5 and 429 in codes[5:]
        r = limited.get("/api/v1/stats", headers={"X-API-Key": key})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_production_refuses_unsafe_configuration():
    from secgraph.errors import ConfigurationError
    from tests.conftest import make_settings

    with pytest.raises(ConfigurationError) as excinfo:
        make_settings(
            "sqlite:///x.db",
            environment="production",
            jwt_secret="change-me-in-production",
            bootstrap_admin_password="admin",
            cors_origins="*",
        ).validate_for_environment()
    message = excinfo.value.message
    assert "JWT_SECRET" in message and "BOOTSTRAP" in message and "PostgreSQL" in message and "CORS" in message
    make_settings(
        "postgresql+psycopg://u:p@db/x", environment="production", jwt_secret="x" * 48
    ).validate_for_environment()

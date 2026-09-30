"""The Python client, the harness connectors and the command line."""

from __future__ import annotations

import io
import json
import sys

import pytest

from secgraph.client import SecurityGraphClient, SecurityGraphError
from secgraph.demo.loader import read_source, seed_demo
from secgraph.governance.rbac import Principal
from secgraph.integrations.ash import GraphAssetConnector, GraphVulnerabilityConnector


@pytest.fixture()
def demo(ctx, tenant):
    principal = Principal.build(id="user:test", name="test", kind="user", tenant_id=tenant, roles=["platform_admin"])
    return seed_demo(ctx, tenant, principal)


@pytest.fixture()
def graph(bridge, auth):
    """The real client, talking to the app in-process."""
    key = auth("analyst", "ingest", "integration")["X-API-Key"]
    sdk = SecurityGraphClient("http://testserver", api_key=key, transport=bridge)
    yield sdk
    sdk.close()


def test_client_covers_the_api(graph, demo):
    assert graph.whoami()["kind"] == "service"
    web = graph.lookup("web-portal-01.dmz.meridian.example", type="Asset", kind="fqdn")[0]
    assert graph.get(web["id"])["name"] == "web-portal-01"
    assert graph.search(types=["Asset"], where={"internet_exposed": True})["total"] == 4
    assert len(list(graph.iter_search(types=["Asset"], page_size=5))) == 16
    assert graph.neighbors(web["id"], edge_types=["HAS_FINDING"], direction="out")["neighbors"]
    assert graph.history(web["id"])[0]["version"] >= 1
    assert graph.subgraph([web["id"]], depth=1)["nodes"]
    cve = graph.lookup("CVE-2021-44228")[0]
    assert graph.shortest_path(web["id"], cve["id"])["length"] == 2
    assert graph.match({"start": {"id": web["id"]}, "steps": [{"edge": "HAS_FINDING"}]})["count"] == 2
    assert graph.stats()["node_total"] == 110
    assert graph.overview()["targets"] == 15
    assert graph.attack_paths(limit=2)["paths"]
    assert graph.exposure(web["id"])["is_entry_point"] is True
    assert graph.blast_radius(web["id"], limit=5)["nodes"]
    assert graph.remediation_priorities(by="asset", limit=3)["items"]
    assert graph.choke_points(limit=3)["items"]
    assert graph.detection_race()["any_target"]
    assert "web-portal-01" in graph.context(web["id"], budget_tokens=800)["text"]
    note = graph.remember("observation", "client test note", "body", entity_ids=[web["id"]], tags=["t"])
    assert note["id"] in [n["id"] for n in graph.recall(entity_id=web["id"])]
    assert graph.feedback(note["id"], "used")["uses"] == 1
    assert isinstance(graph.suggest(entity_ids=[web["id"]]), list)
    out = graph.ingest("client-test", nodes=[{"type": "Asset", "identifiers": {"fqdn": "sdk-1.corp.example"}}])
    assert out["nodes"]["created"] == 1
    mapped = graph.ingest_source("epss_csv", read_source("epss.csv"))
    assert mapped["nodes"]["unchanged"] == 11
    events = list(graph.iter_changes(after=0, kinds=["node.created"]))
    assert events and all(e["kind"] == "node.created" for e in events)
    assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)


def test_client_raises_typed_errors(graph, bridge):
    with pytest.raises(SecurityGraphError) as excinfo:
        graph.get("0" * 32)
    assert excinfo.value.status == 404 and excinfo.value.code == "not_found" and excinfo.value.request_id
    with pytest.raises(SecurityGraphError) as excinfo:
        graph.search(types=["Nope"])
    assert excinfo.value.code == "validation_failed"
    anonymous = SecurityGraphClient("http://testserver", transport=bridge)
    with pytest.raises(SecurityGraphError) as excinfo:
        anonymous.stats()
    assert excinfo.value.status == 401


def test_client_retries_reads_but_never_writes(monkeypatch):
    import httpx

    from secgraph import client as client_module

    monkeypatch.setattr(client_module.time, "sleep", lambda _seconds: None)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET" and len(calls) == 1:
            raise httpx.ConnectError("connection refused")
        if request.method == "GET" and len(calls) == 2:
            return httpx.Response(503, json={"error": {"code": "unavailable", "message": "starting"}})
        if request.method == "GET":
            return httpx.Response(200, json={"nodes": {}, "edges": {}})
        return httpx.Response(503, json={"error": {"code": "unavailable", "message": "starting"}})

    graph = SecurityGraphClient("http://graph.test", api_key="k", transport=httpx.MockTransport(handler))
    assert graph.stats() == {"nodes": {}, "edges": {}}
    assert calls == ["GET", "GET", "GET"]  # one connection failure, one 503, then success

    calls.clear()
    with pytest.raises(SecurityGraphError) as error:
        graph.ingest("cmdb", nodes=[])
    assert error.value.status == 503 and calls == ["POST"]  # a write is sent exactly once

    calls.clear()
    impatient = SecurityGraphClient("http://graph.test", retries=0, transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.ConnectError):
        impatient.stats()


def test_client_password_login(bridge, ctx, tenant):
    import uuid

    username = f"sdk-{uuid.uuid4().hex[:8]}"
    ctx.auth.create_user(tenant, "user:test", username=username, password="Correct-Horse-9", roles=["viewer"])
    sdk = SecurityGraphClient("http://testserver", transport=bridge)
    assert sdk.login(username, "Correct-Horse-9")["token_type"] == "bearer"
    assert sdk.whoami()["name"] == username


def test_harness_connectors(graph, demo):
    assets, vulns = GraphAssetConnector(graph), GraphVulnerabilityConnector(graph)
    by_hostname = assets.get_asset("web-portal-01")
    assert by_hostname["found"] and by_hostname["criticality"] == 4 and by_hostname["internet_exposed"] is True
    assert by_hostname["exposure"]["is_entry_point"] is True and "waf" in by_hostname["exposure"]["controls"]
    by_ip = assets.get_asset("10.20.0.5")
    assert by_ip["name"] == "ad-dc-01"
    by_graph_id = assets.get_asset(by_ip["graph_id"])
    assert by_graph_id["name"] == "ad-dc-01"
    assert assets.get_asset("no-such-host") == {"asset_id": "no-such-host", "found": False}
    found = vulns.get_vulnerabilities("web-portal-01.dmz.meridian.example")
    assert found["count"] == 2 and found["known_exploited"] == 1
    assert found["vulnerabilities"][0]["vulnerability"] == "CVE-2021-44228"  # most exploitable first
    assert vulns.get_vulnerabilities("ghost")["vulnerabilities"] == []
    try:  # when the harness is installed, the classes satisfy its runtime-checkable protocols
        from ash.connectors.base import AssetConnector, VulnerabilityConnector
    except ImportError:
        return
    assert isinstance(assets, AssetConnector) and isinstance(vulns, VulnerabilityConnector)


def test_vulnerability_connector_without_analytics_permission(bridge, auth, demo):
    key = auth("viewer")["X-API-Key"]
    sdk = SecurityGraphClient("http://testserver", api_key=key, transport=bridge)
    found = GraphVulnerabilityConnector(sdk).get_vulnerabilities("web-portal-01")
    assert found["count"] == 2 and {v["vulnerability"] for v in found["vulnerabilities"]} == {
        "CVE-2021-44228",
        "CVE-2022-42889",
    }
    assert "exposure" not in GraphAssetConnector(sdk).get_asset("web-portal-01")


# ---- command line -----------------------------------------------------------
@pytest.fixture()
def cli(tmp_path, monkeypatch, capsys):
    """Run ``secgraph`` in-process against a private SQLite database."""
    from secgraph import cli as cli_module
    from secgraph.config import set_settings
    from secgraph.ontology import reset_ontology_cache

    monkeypatch.setenv("SECGRAPH_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("SECGRAPH_LOG_JSON", "false")
    monkeypatch.setenv("SECGRAPH_ENVIRONMENT", "development")
    monkeypatch.chdir(tmp_path)
    set_settings(None)
    reset_ontology_cache()

    def run(*argv: str, stdin: str | None = None) -> tuple[int, str, str]:
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        try:
            code = cli_module.main(list(argv))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            if not isinstance(exc.code, int) and exc.code:
                print(exc.code, file=sys.stderr)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    yield run
    set_settings(None)


def test_cli_end_to_end(cli, tmp_path, settings):
    code, out, _ = cli("doctor")
    assert code == 1 and "FAIL  schema" in out  # not migrated yet
    assert cli("migrate", "status")[0] == 1
    code, out, _ = cli("migrate")
    assert code == 0 and json.loads(out)["up_to_date"] is True
    code, out, _ = cli("doctor")
    assert code == 0 and "FAIL" not in out and "10 mappings" in out

    code, out, _ = cli("seed-demo")
    assert code == 0 and "110 nodes, 185 edges" in out and "crown jewels at risk" in out
    code, out, _ = cli("seed-demo", "--json")
    assert all(s["nodes"]["created"] == 0 for s in json.loads(out)["sources"])  # idempotent

    code, out, _ = cli("report", "overview", "--limit", "3")
    assert code == 0 and json.loads(out)["entry_points"] == 4
    code, out, _ = cli("report", "priorities", "--by", "asset", "--limit", "2")
    assert len(json.loads(out)["items"]) == 2

    code, out, err = cli(
        "users", "create", "asha", "--roles", "analyst,steward", "--password-stdin", stdin="Correct-Horse-9\n"
    )
    assert code == 0 and json.loads(out)["roles"] == ["analyst", "steward"]
    code, _, err = cli("users", "create", "weak", "--password-stdin", stdin="short\n")
    assert code == 1 and "at least 12" in err
    assert cli("users", "create")[0] == 1
    assert cli("users", "disable", "asha")[0] == 0
    code, out, _ = cli("users", "list")
    assert json.loads(out)[0]["disabled"] is True

    code, out, err = cli("keys", "create", "--name", "hal-o", "--roles", "agent", "--kind", "agent")
    key = json.loads(out)
    assert code == 0 and key["api_key"].startswith("sg_") and "cannot be shown again" in err
    assert cli("keys", "revoke", key["id"])[0] == 0
    code, out, _ = cli("keys", "list")
    assert json.loads(out)[0]["revoked_at"]

    source = tmp_path / "assets.csv"
    source.write_text("fqdn,criticality\ncli-1.corp.example,3\n,4\n", encoding="utf-8")
    code, out, _ = cli("ingest", str(source), "--mapping", "assets_csv", "--tenant", "other")
    assert code == 2 and json.loads(out)["nodes"]["created"] == 1  # exit code 2: something was quarantined
    batch = tmp_path / "batch.json"
    batch.write_text(
        json.dumps({"source": "cli", "nodes": [{"type": "Asset", "identifiers": {"fqdn": "cli-2.corp.example"}}]}),
        encoding="utf-8",
    )
    code, out, _ = cli("ingest", str(batch), "--tenant", "other")
    assert code == 0 and json.loads(out)["nodes"]["created"] == 1
    assert cli("ingest", str(source), "--mapping", "nope")[0] == 1

    code, out, _ = cli("mappings")
    assert "cyclonedx" in out and "asset_fqdn" in out
    code, out, _ = cli("ontology", "validate")
    assert code == 0 and "17 node types" in out and "10 mappings are consistent" in out
    code, out, _ = cli("ontology", "docs")
    assert out.startswith("# Ontology reference")
    assert json.loads(cli("ontology", "show")[1])["ontology"]["version"] == "1.0.0"
    code, out, _ = cli("verify-audit")
    assert code == 0 and json.loads(out)["ok"] is True

    vault = tmp_path / "vault"
    code, out, _ = cli("export-vault", str(vault))
    assert code == 0 and json.loads(out)["entities"] == 110
    assert (vault / "CLAUDE.md").is_file() and (vault / "analytics" / "overview.md").is_file()
    assert len(list((vault / "Asset").glob("*.md"))) == 17  # 16 assets and the index

    code, out, _ = cli("worker", "--once")
    assert code == 0 and json.loads(out)["maintenance"]["tenants"] == 2

    bad_ontology = tmp_path / "bad.yaml"
    bad_ontology.write_text("ontology: {name: x, version: 1.0.0}\nnode_types: {}\nedge_types: {}\n", encoding="utf-8")
    code, _, err = cli("ontology", "validate", str(bad_ontology))
    assert code == 1 and "invalid ontology" in err
    assert cli("migrate", "downgrade")[0] == 1  # refuses without --yes


def test_cli_mcp_over_stdio(cli):
    cli("migrate")
    cli("seed-demo")
    requests = (
        "\n".join(
            json.dumps(m)
            for m in [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "graph_stats", "arguments": {}}},
            ]
        )
        + "\nnot json\n"
    )
    code, out, _ = cli("mcp", stdin=requests)
    assert code == 0
    responses = [json.loads(line) for line in out.strip().splitlines()]
    assert [r.get("id") for r in responses] == [1, 2, 3, None]
    assert responses[0]["result"]["serverInfo"]["name"] == "security-graph"
    assert len(responses[1]["result"]["tools"]) == 18
    assert json.loads(responses[2]["result"]["content"][0]["text"])["node_total"] == 110
    assert responses[3]["error"]["code"] == -32700

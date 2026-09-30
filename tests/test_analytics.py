"""Analytics on a stored graph, against hand-computed expectations."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secgraph.analytics.service import AnalyticsService
from secgraph.errors import NotFound, ValidationFailed
from secgraph.governance.rbac import FULL_SCOPE, AccessScope


@pytest.fixture()
def analytics(db, ontology, settings):
    return AnalyticsService(db, ontology, settings)


@pytest.fixture()
def chain(load):
    """internet → web (KEV, WAF 0.5) → app (EPSS 0.4) → svc account → db (crown jewel) → customer data.

    Step probabilities, by hand:
      entry   attacker→web  max(0.02, 0.9 KEV) × (1 − 0.5 WAF)  = 0.45
      lateral web→app       0.4 (EPSS beats 0.3 × 7.5/10)       = 0.40
      creds   app→svc       fixed                               = 0.60
      access  svc→db        privilege admin                     = 0.95
      data    db→customers  fixed                               = 0.90
    """
    result = load(
        nodes=[
            {
                "type": "Asset",
                "identifiers": {"fqdn": "web-01.dmz.example"},
                "properties": {"internet_exposed": True, "criticality": 3},
                "ref": "web",
            },
            {
                "type": "Asset",
                "identifiers": {"fqdn": "app-01.core.example"},
                "properties": {"criticality": 3},
                "ref": "app",
            },
            {
                "type": "Asset",
                "identifiers": {"fqdn": "db-01.core.example"},
                "properties": {"criticality": 5, "crown_jewel": True},
                "ref": "db",
            },
            {
                "type": "Identity",
                "identifiers": {"account": "corp\\svc-app"},
                "properties": {"identity_type": "service"},
                "ref": "svc",
            },
            {
                "type": "DataStore",
                "identifiers": {"datastore_key": "customers"},
                "properties": {"name": "Customer master", "classification": "restricted", "contains_pii": True},
                "ref": "data",
            },
            {
                "type": "Vulnerability",
                "identifiers": {"cve": "CVE-2021-44228"},
                "properties": {"kev": True, "cvss_score": 10.0, "epss": 0.5},
                "ref": "cve_a",
            },
            {
                "type": "Vulnerability",
                "identifiers": {"cve": "CVE-2023-0001"},
                "properties": {"cvss_score": 7.5, "epss": 0.4},
                "ref": "cve_b",
            },
            {"type": "Finding", "identifiers": {"finding_key": "f1"}, "properties": {"status": "open"}, "ref": "f1"},
            {"type": "Finding", "identifiers": {"finding_key": "f2"}, "properties": {"status": "open"}, "ref": "f2"},
            {
                "type": "Finding",
                "identifiers": {"finding_key": "f3"},
                "properties": {"status": "resolved"},
                "ref": "f3",
            },
            {
                "type": "Control",
                "identifiers": {"control_key": "waf-edge"},
                "properties": {"control_type": "waf", "effectiveness": 0.5, "status": "active"},
                "ref": "waf",
            },
            {
                "type": "BusinessService",
                "identifiers": {"service_key": "payments"},
                "properties": {"name": "Payments", "criticality": 5, "regulatory_tags": ["RBI"]},
                "ref": "pay",
            },
            {
                "type": "BusinessService",
                "identifiers": {"service_key": "reporting"},
                "properties": {"name": "Regulatory reporting", "criticality": 3},
                "ref": "rep",
            },
        ],
        edges=[
            {"type": "HAS_FINDING", "source": {"ref": "web"}, "target": {"ref": "f1"}},
            {"type": "INSTANCE_OF", "source": {"ref": "f1"}, "target": {"ref": "cve_a"}},
            {"type": "HAS_FINDING", "source": {"ref": "app"}, "target": {"ref": "f2"}},
            {"type": "INSTANCE_OF", "source": {"ref": "f2"}, "target": {"ref": "cve_b"}},
            {"type": "HAS_FINDING", "source": {"ref": "db"}, "target": {"ref": "f3"}},  # resolved: ignored
            {"type": "INSTANCE_OF", "source": {"ref": "f3"}, "target": {"ref": "cve_a"}},
            {"type": "PROTECTS", "source": {"ref": "waf"}, "target": {"ref": "web"}},
            {"type": "CONNECTS_TO", "source": {"ref": "web"}, "target": {"ref": "app"}, "key": "tcp/8443"},
            {"type": "CONNECTS_TO", "source": {"ref": "web"}, "target": {"ref": "app"}, "key": "tcp/22"},
            {"type": "CONNECTS_TO", "source": {"ref": "web"}, "target": {"ref": "db"}},  # db has nothing open
            {"type": "HAS_SESSION", "source": {"ref": "app"}, "target": {"ref": "svc"}},
            {
                "type": "HAS_ACCESS",
                "source": {"ref": "svc"},
                "target": {"ref": "db"},
                "properties": {"privilege": "admin"},
            },
            {"type": "HOSTS", "source": {"ref": "db"}, "target": {"ref": "data"}},
            {"type": "SUPPORTS", "source": {"ref": "db"}, "target": {"ref": "pay"}},
            {"type": "DEPENDS_ON", "source": {"ref": "rep"}, "target": {"ref": "pay"}},
        ],
    )
    assert not result.rejections
    return result.refs


P_DB = 0.45 * 0.4 * 0.6 * 0.95
P_DATA = P_DB * 0.9
RISK = 16 * P_DB + 12 * P_DATA


def test_overview_matches_hand_calculation(tenant, analytics, chain):
    out = analytics.overview(tenant, FULL_SCOPE)
    assert out["graph"]["states"] == 5 and out["graph"]["steps"] == 5
    assert out["entry_points"] == 1 and out["targets"] == 2 and out["targets_at_risk"] == 2
    assert out["risk"]["lower"] == pytest.approx(RISK, abs=1e-5)
    assert out["risk"]["upper"] == pytest.approx(RISK, abs=1e-5)  # a pure chain: every bound coincides
    assert out["risk"]["estimate"] == pytest.approx(RISK, abs=1e-5)
    top = out["top_targets"]
    assert [t["id"] for t in top] == [chain["db"], chain["data"]]
    assert top[0]["impact"] == 16 and top[0]["probability"]["method"] == "exact"
    assert top[0]["probability"]["estimate"] == pytest.approx(P_DB, abs=1e-6)
    assert top[1]["impact"] == 12 and top[1]["probability"]["upper"] == pytest.approx(P_DATA, abs=1e-6)
    assert out["exposure"] == {"open_findings": 2, "known_exploited": 1, "risk_accepted": 0, "states_with_findings": 2}


def test_attack_paths_explain_every_step(tenant, analytics, chain):
    out = analytics.attack_paths(tenant, FULL_SCOPE)
    assert [p["target"]["id"] for p in out["paths"]] == [chain["db"], chain["data"]]
    path = out["paths"][0]
    assert path["probability"] == pytest.approx(P_DB, abs=1e-6)
    assert path["risk"] == pytest.approx(16 * P_DB, abs=1e-5)
    assert [s["technique"] for s in path["steps"]] == [
        "internet_exposed_asset",
        "lateral_exploit",
        "credential_theft",
        "use_access",
    ]
    assert [s["probability"] for s in path["steps"]] == pytest.approx([0.45, 0.4, 0.6, 0.95])
    entry = path["steps"][0]
    assert entry["from"]["type"] == "Attacker" and entry["to"]["id"] == chain["web"]
    assert entry["basis"]["model"] == "exploitability"
    assert entry["basis"]["findings"][0]["basis"] == "kev"
    assert entry["basis"]["findings"][0]["vulnerability"] == "CVE-2021-44228"
    assert entry["basis"]["combined_exploitability"] == pytest.approx(0.9)
    assert entry["basis"]["control_multiplier"] == pytest.approx(0.5)
    assert [c["control_type"] for c in entry["controls_applied"]] == ["waf"]
    assert "waf" not in entry["recommended_controls"] and "patch_management" in entry["recommended_controls"]
    lateral = path["steps"][1]
    assert lateral["basis"]["findings"][0]["basis"] == "epss" and lateral["edge_id"]
    assert path["steps"][3]["basis"] == {
        "model": "by_property",
        "base": 0.95,
        "control_multiplier": 1.0,
        "formula": "base × Π(1 - control effectiveness)",
        "property": "privilege",
    }
    assert path["target_compromise"]["lower"] == pytest.approx(P_DB, abs=1e-6)


def test_k_paths_to_one_target_and_assumed_foothold(tenant, analytics, chain):
    out = analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["data"], k=3)
    assert len(out["paths"]) == 1 and out["paths"][0]["length"] == 5
    assert out["paths"][0]["probability"] == pytest.approx(P_DATA, abs=1e-6)
    inside = analytics.attack_paths(tenant, FULL_SCOPE, source_id=chain["app"])
    assert inside["source"]["id"] == chain["app"]
    assert [p["probability"] for p in inside["paths"]] == pytest.approx([0.6 * 0.95, 0.6 * 0.95 * 0.9], abs=1e-6)
    assert "target_compromise" not in inside["paths"][0]
    with pytest.raises(NotFound):
        analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["cve_a"])  # a CVE is not an attacker state
    with pytest.raises(ValidationFailed):
        analytics.attack_paths(tenant, FULL_SCOPE, k=0)
    with pytest.raises(ValidationFailed):
        analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["app"], source_id=chain["app"])


def test_remediation_priorities_recompute_the_graph_per_fix(tenant, analytics, chain):
    out = analytics.remediation_priorities(tenant, FULL_SCOPE, by="finding")
    assert out["risk_before"] == pytest.approx(RISK, abs=1e-5)
    assert out["candidates"] == 2 and out["partial"] is False
    first, second = out["items"]
    # Fixing the internal finding severs the only route: all risk goes.
    assert first["key"] == chain["f2"]
    assert first["risk_reduction"] == pytest.approx(RISK, abs=1e-5) and first["risk_reduction_percent"] == 100.0
    # Fixing the internet-facing KEV still leaves the 2% residual for an exposed asset (× WAF 0.5).
    assert second["key"] == chain["f1"] and second["known_exploited"] is True
    assert second["risk_after"] == pytest.approx(RISK * (0.02 * 0.5) / 0.45, abs=1e-5)
    assert second["finding"]["vulnerability"] == "CVE-2021-44228"
    assert {t["id"] for t in first["protects"]} == {chain["db"], chain["data"]}
    assert first["protects"][0]["probability_drop"] == pytest.approx(P_DB, abs=1e-6)

    by_vuln = analytics.remediation_priorities(tenant, FULL_SCOPE, by="vulnerability")
    assert {i["vulnerability"] for i in by_vuln["items"]} == {"CVE-2021-44228", "CVE-2023-0001"}
    by_asset = analytics.remediation_priorities(tenant, FULL_SCOPE, by="asset")
    assert {i["key"] for i in by_asset["items"]} == {chain["web"], chain["app"]}
    with pytest.raises(ValidationFailed):
        analytics.remediation_priorities(tenant, FULL_SCOPE, by="colour")


def test_choke_points(tenant, analytics, chain):
    out = analytics.choke_points(tenant, FULL_SCOPE)
    by_id = {i["id"]: i for i in out["items"]}
    for key in ("web", "app", "svc"):
        assert by_id[chain[key]]["risk_reduction"] == pytest.approx(RISK, abs=1e-5)
    # db is itself a target: blocking it protects the data behind it; its own impact is not counted as "downstream"
    assert by_id[chain["db"]]["risk_reduction"] == pytest.approx(12 * P_DATA, abs=1e-5)
    assert "credential_guard" in by_id[chain["svc"]]["recommended_controls"]


def test_blast_radius_and_business_impact(tenant, analytics, chain):
    out = analytics.blast_radius(tenant, FULL_SCOPE, chain["app"])
    got = {n["id"]: n["probability"]["estimate"] for n in out["nodes"]}
    assert got == pytest.approx({chain["svc"]: 0.6, chain["db"]: 0.57, chain["data"]: 0.513}, abs=1e-6)
    assert out["targets_reachable"] == 2
    assert out["expected_impact"] == pytest.approx(16 * 0.57 + 12 * 0.513, abs=1e-5)
    services = {s["name"]: s for s in out["business_services"]}
    assert services["Payments"]["probability_at_least"] == pytest.approx(0.57, abs=1e-6)
    assert services["Payments"]["via"]["id"] == chain["db"] and services["Payments"]["regulatory_tags"] == ["RBI"]
    # reporting depends on payments, which depends on db
    assert services["Regulatory reporting"]["probability_at_least"] == pytest.approx(0.57, abs=1e-6)
    assert [s["name"] for s in out["business_services"]] == ["Payments", "Regulatory reporting"]
    edge = analytics.blast_radius(tenant, FULL_SCOPE, chain["data"])
    assert edge["reachable"] == 0 and edge["business_services"] == []


def test_node_exposure(tenant, analytics, chain):
    out = analytics.node_exposure(tenant, FULL_SCOPE, chain["app"])
    assert out["is_entry_point"] is False
    assert out["compromise_probability"]["estimate"] == pytest.approx(0.18, abs=1e-6)
    assert out["most_likely_path"]["length"] == 2
    assert out["open_finding_count"] == 1 and out["open_findings"][0]["vulnerability"] == "CVE-2023-0001"
    assert [t["id"] for t in out["targets_reachable"]] == [chain["db"], chain["data"]]
    web = analytics.node_exposure(tenant, FULL_SCOPE, chain["web"])
    assert web["is_entry_point"] is True and [c["control_type"] for c in web["controls"]] == ["waf"]


def test_detection_race_hand_computed(tenant, analytics, chain):
    out = analytics.detection_race(tenant, FULL_SCOPE, target_id=chain["db"])
    d = 0.02
    expected = 1.0
    attempts = 1 / 0.45  # from outside: no detection, retry until the entry works
    for p in (0.4, 0.6, 0.95):
        den = d + (1 - d) * p
        attempts += expected / den
        expected *= (1 - d) * p / den
    assert out["reach_before_detection"] == pytest.approx(expected, abs=1e-6)
    assert out["detected_first"] == pytest.approx(1 - expected, abs=1e-6)
    assert out["expected_attempts"] == pytest.approx(attempts, abs=1e-3)
    overall = analytics.detection_race(tenant, FULL_SCOPE)
    assert overall["any_target"]["reach_before_detection"] == pytest.approx(expected, abs=1e-6)
    assert [t["target"]["id"] for t in overall["per_target"]] == [chain["db"], chain["data"]]


def test_graph_cache_follows_the_change_feed(tenant, analytics, chain, load):
    first = analytics.graph(tenant)
    assert analytics.graph(tenant) is first  # nothing changed: reused
    load(nodes=[{"type": "Finding", "identifiers": {"finding_key": "f2"}, "properties": {"status": "resolved"}}])
    second = analytics.graph(tenant)
    assert second is not first and second.change_seq > first.change_seq
    out = analytics.overview(tenant, FULL_SCOPE)
    assert out["risk"]["upper"] == 0 and out["targets_at_risk"] == 0


def test_analytics_as_of_a_past_time(tenant, analytics, chain, load):
    before = datetime.now(UTC)
    load(nodes=[{"type": "Finding", "identifiers": {"finding_key": "f2"}, "properties": {"status": "resolved"}}])
    assert analytics.overview(tenant, FULL_SCOPE)["risk"]["upper"] == 0
    past = analytics.overview(tenant, FULL_SCOPE, as_of=before)
    assert past["risk"]["upper"] == pytest.approx(RISK, abs=1e-5)
    assert past["graph"]["as_of"] is not None


def test_compensating_control_on_a_finding_and_risk_acceptance(tenant, analytics, chain, load):
    load(
        nodes=[
            {
                "type": "Control",
                "identifiers": {"control_key": "vpatch-7"},
                "properties": {"control_type": "virtual_patching", "effectiveness": 0.8},
                "ref": "vp",
            },
            {
                "type": "Finding",
                "identifiers": {"finding_key": "f2"},
                "properties": {"status": "risk_accepted", "exception_until": "2027-03-31"},
                "ref": "f2",
            },
        ],
        edges=[{"type": "MITIGATES", "source": {"ref": "vp"}, "target": {"ref": "f2"}}],
    )
    out = analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["db"])
    lateral = out["paths"][0]["steps"][1]
    assert lateral["probability"] == pytest.approx(0.4 * 0.2)  # accepted risk still counts; the virtual patch helps
    finding = lateral["basis"]["findings"][0]
    assert finding["status"] == "risk_accepted" and finding["exception_until"].startswith("2027-03-31")
    assert finding["compensating_controls"][0]["control_type"] == "virtual_patching"
    assert analytics.overview(tenant, FULL_SCOPE)["exposure"]["risk_accepted"] == 1


def test_degraded_and_inactive_controls(tenant, analytics, chain, load):
    load(nodes=[{"type": "Control", "identifiers": {"control_key": "waf-edge"}, "properties": {"status": "degraded"}}])
    path = analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["db"])["paths"][0]
    assert path["steps"][0]["probability"] == pytest.approx(0.9 * (1 - 0.25))  # 0.5 effectiveness halved
    load(nodes=[{"type": "Control", "identifiers": {"control_key": "waf-edge"}, "properties": {"status": "inactive"}}])
    path = analytics.attack_paths(tenant, FULL_SCOPE, target_id=chain["db"])["paths"][0]
    assert path["steps"][0]["probability"] == pytest.approx(0.9) and path["steps"][0]["controls_applied"] == []


def test_many_neighbours_attacking_one_host_share_one_exploit_event(tenant, analytics, load):
    """Ten compromised neighbours do not make a 30% exploit a near-certainty."""
    nodes = [
        {
            "type": "NetworkSegment",
            "identifiers": {"segment_key": "internet"},
            "properties": {"zone": "internet"},
            "ref": "net",
        },
        {
            "type": "Asset",
            "identifiers": {"fqdn": "target.core.example"},
            "properties": {"crown_jewel": True, "criticality": 5},
            "ref": "t",
        },
        {"type": "Vulnerability", "identifiers": {"cve": "CVE-2024-1111"}, "properties": {"epss": 0.3}, "ref": "v"},
        {"type": "Finding", "identifiers": {"finding_key": "ft"}, "ref": "f"},
    ]
    edges = [
        {"type": "HAS_FINDING", "source": {"ref": "t"}, "target": {"ref": "f"}},
        {"type": "INSTANCE_OF", "source": {"ref": "f"}, "target": {"ref": "v"}},
    ]
    for i in range(10):
        # each neighbour sits in the internet segment with a certain exploit, so the attacker holds all ten
        nodes += [
            {"type": "Asset", "identifiers": {"fqdn": f"n{i}.dmz.example"}, "ref": f"n{i}"},
            {
                "type": "Vulnerability",
                "identifiers": {"cve": f"CVE-2024-20{i:02d}"},
                "properties": {"epss": 0.99},
                "ref": f"v{i}",
            },
            {"type": "Finding", "identifiers": {"finding_key": f"fn{i}"}, "ref": f"f{i}"},
        ]
        edges += [
            {"type": "IN_SEGMENT", "source": {"ref": f"n{i}"}, "target": {"ref": "net"}},
            {"type": "HAS_FINDING", "source": {"ref": f"n{i}"}, "target": {"ref": f"f{i}"}},
            {"type": "INSTANCE_OF", "source": {"ref": f"f{i}"}, "target": {"ref": f"v{i}"}},
            {"type": "CONNECTS_TO", "source": {"ref": f"n{i}"}, "target": {"ref": "t"}},
        ]
    refs = load(nodes=nodes, edges=edges).refs
    out = analytics.overview(tenant, FULL_SCOPE)
    probability = out["top_targets"][0]["probability"]
    assert out["top_targets"][0]["id"] == refs["t"]
    assert probability["lower"] == pytest.approx(0.99 * 0.3, abs=1e-6)
    # Independent attempts would give 1 − 0.7^10 ≈ 0.97. Sharing the exploit event keeps it at ≤ 0.3.
    assert probability["upper"] == pytest.approx(0.3, abs=1e-3)
    assert probability["lower"] <= probability["estimate"] <= probability["upper"]


def test_ai_plane_path_through_a_poisoned_knowledge_base(tenant, analytics, load):
    """Internet-facing wiki → knowledge base the agent reads → agent → tool → core banking host."""
    refs = load(
        nodes=[
            {
                "type": "Asset",
                "identifiers": {"fqdn": "wiki.dmz.example"},
                "properties": {"internet_exposed": True},
                "ref": "wiki",
            },
            {
                "type": "Vulnerability",
                "identifiers": {"cve": "CVE-2023-22515"},
                "properties": {"kev": True},
                "ref": "v",
            },
            {"type": "Finding", "identifiers": {"finding_key": "wiki-f"}, "ref": "f"},
            {
                "type": "DataStore",
                "identifiers": {"datastore_key": "runbooks"},
                "properties": {"store_type": "knowledge_base", "classification": "internal"},
                "ref": "kb",
            },
            {
                "type": "AIAgent",
                "identifiers": {"agent_key": "triage-agent"},
                "properties": {"autonomy_level": "autonomous"},
                "ref": "agent",
            },
            {
                "type": "Tool",
                "identifiers": {"tool_key": "isolate_host"},
                "properties": {"risk_tier": "high"},
                "ref": "tool",
            },
            {
                "type": "Asset",
                "identifiers": {"fqdn": "cbs-01.core.example"},
                "properties": {"crown_jewel": True, "criticality": 5},
                "ref": "cbs",
            },
            {
                "type": "Control",
                "identifiers": {"control_key": "thoth"},
                "properties": {"control_type": "semantic_firewall", "effectiveness": 0.6},
                "ref": "thoth",
            },
        ],
        edges=[
            {"type": "HAS_FINDING", "source": {"ref": "wiki"}, "target": {"ref": "f"}},
            {"type": "INSTANCE_OF", "source": {"ref": "f"}, "target": {"ref": "v"}},
            {"type": "HOSTS", "source": {"ref": "wiki"}, "target": {"ref": "kb"}},
            {"type": "READS_FROM", "source": {"ref": "agent"}, "target": {"ref": "kb"}},
            {"type": "CAN_INVOKE", "source": {"ref": "agent"}, "target": {"ref": "tool"}},
            {
                "type": "TOOL_TARGETS",
                "source": {"ref": "tool"},
                "target": {"ref": "cbs"},
                "properties": {"effect": "execute"},
            },
            {"type": "PROTECTS", "source": {"ref": "thoth"}, "target": {"ref": "agent"}},
        ],
    ).refs
    path = analytics.attack_paths(tenant, FULL_SCOPE, target_id=refs["cbs"])["paths"][0]
    assert [s["technique"] for s in path["steps"]] == [
        "internet_exposed_asset",
        "data_on_host",
        "indirect_prompt_injection",
        "tool_invocation",
        "tool_effect",
    ]
    assert [s["probability"] for s in path["steps"]] == pytest.approx([0.9, 0.9, 0.3 * 0.4, 0.8, 0.9])
    injection = path["steps"][2]
    assert [c["control_type"] for c in injection["controls_applied"]] == ["semantic_firewall"]
    assert injection["recommended_controls"] == ["llm_firewall", "agent_policy_enforcement"]


def test_identity_names_are_masked_in_analytics_without_pii(tenant, analytics, load):
    load(
        nodes=[
            {
                "type": "Asset",
                "identifiers": {"fqdn": "vpn.dmz.example"},
                "properties": {"internet_exposed": True},
                "ref": "vpn",
            },
            {
                "type": "Identity",
                "identifiers": {"upn": "ravi.kumar@example.com"},
                "properties": {"display_name": "Ravi Kumar", "privileged": True},
                "ref": "admin",
            },
        ],
        edges=[{"type": "HAS_SESSION", "source": {"ref": "vpn"}, "target": {"ref": "admin"}}],
    )
    out = analytics.attack_paths(tenant, AccessScope(pii=False))
    assert "Ravi" not in str(out) and out["paths"][0]["target"]["name"].startswith("Identity-")
    assert "Ravi Kumar" in str(analytics.attack_paths(tenant, FULL_SCOPE))


def test_empty_tenant(tenant, analytics):
    out = analytics.overview(tenant, FULL_SCOPE)
    assert out["targets"] == 0 and out["risk"]["upper"] == 0 and out["top_targets"] == []
    assert analytics.attack_paths(tenant, FULL_SCOPE)["paths"] == []
    assert analytics.remediation_priorities(tenant, FULL_SCOPE)["items"] == []
    assert analytics.choke_points(tenant, FULL_SCOPE)["items"] == []
    assert analytics.detection_race(tenant, FULL_SCOPE)["any_target"] is None


def test_parameters_expose_the_whole_model(analytics):
    out = analytics.parameters()
    assert out["exploitability"]["kev_floor"] == 0.9
    assert {t["name"] for t in out["transitions"]} >= {"lateral_exploit", "indirect_prompt_injection"}
    assert "compromise_upper" in out["formulas"]

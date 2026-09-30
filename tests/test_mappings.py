"""Every shipped mapping, against a realistic sample of its source format."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from secgraph.demo.loader import read_source
from secgraph.errors import ConfigurationError, NotFound, ValidationFailed
from secgraph.governance.rbac import FULL_SCOPE
from secgraph.ingest.mapping import Mapping, MappingRegistry, compile_path, walk
from secgraph.ingest.pipeline import ingest_source
from secgraph.query.service import QueryService
from secgraph.store.models import QuarantinedRecord
from secgraph.store.repository import GraphReader


@pytest.fixture(scope="module")
def registry(ontology):
    return MappingRegistry(ontology)


@pytest.fixture()
def run(ingest_service, registry, settings, tenant):
    def _run(mapping, payload, **kwargs):
        return ingest_source(ingest_service, registry, settings, tenant, "user:test", mapping, payload, **kwargs)

    return _run


@pytest.fixture()
def find(db, tenant, ontology, settings):
    query = QueryService(ontology, settings)

    def _find(value, node_type=None, kind=None):
        with db.transaction() as s:
            found = query.find_by_identifier(s, tenant, FULL_SCOPE, value=value, node_type=node_type, kind=kind)
        assert len(found) == 1, f"{value}: {len(found)} matches"
        return found[0]

    return _find


def neighbours(db, tenant, node_id, edge_type, direction="out"):
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        edges, _ = reader.edges_of([node_id], direction=direction, types=[edge_type])
        others = reader.get_nodes([e.target if direction == "out" else e.source for e in edges])
        return sorted(n.name for n in others.values())


# ---- path language ----------------------------------------------------------
def test_path_language():
    doc = {
        "a": {"b": [{"c": 1, "k": "x"}, {"c": 2, "k": "y"}, {"k": "x", "c": 3}]},
        "e": [[1, 2], [3]],
        "w": [{"d": [{"v": "p"}, {"v": "q"}]}, {"d": [{"v": "r"}]}],
    }
    assert walk(doc, compile_path(".a.b[0].c")) == 1
    assert walk(doc, compile_path(".a.b[*].c")) == [1, 2, 3]
    assert walk(doc, compile_path(".a.b[?k=x].c")) == [1, 3]
    assert walk(doc, compile_path(".w[*].d[*].v")) == ["p", "q", "r"]
    assert walk(doc, compile_path(".a.missing.c")) is None
    assert walk(doc, compile_path(".a.b[9].c")) is None
    assert walk(doc, compile_path(".a.b[*].nope")) == []
    with pytest.raises(ValueError):
        compile_path(".a b")


def test_registry_lists_and_rejects_unknown(registry):
    assert set(registry.names()) >= {
        "assets_csv",
        "cyclonedx",
        "nvd_cve",
        "cisa_kev",
        "epss_csv",
        "attack_stix",
        "vuln_findings_csv",
        "identities_csv",
        "ocsf_vulnerability_finding",
        "ocsf_detection_finding",
    }
    assert all(d["description"] for d in registry.describe())
    with pytest.raises(NotFound):
        registry.get("nope")


@pytest.mark.parametrize(
    "bad, message",
    [
        (
            {
                "mapping": {"name": "x1", "source": "s"},
                "emit": [{"node": {"type": "Nope", "identifiers": {"a": "$.a"}}}],
            },
            "unknown node type",
        ),
        (
            {
                "mapping": {"name": "x1", "source": "s"},
                "emit": [{"node": {"type": "Asset", "identifiers": {"nope": "$.a"}}}],
            },
            "no identifier 'nope'",
        ),
        (
            {
                "mapping": {"name": "x1", "source": "s"},
                "emit": [{"edge": {"type": "RUNS", "source": {"ref": "ghost"}, "target": {"ref": "ghost"}}}],
            },
            "not defined",
        ),
        (
            {
                "mapping": {"name": "x1", "source": "s"},
                "emit": [
                    {
                        "edge": {
                            "type": "RUNS",
                            "source": {"type": "Finding", "identifiers": {"finding_key": "$.a"}},
                            "target": {"type": "Software", "identifiers": {"purl": "$.p"}},
                        }
                    }
                ],
            },
            "does not allow Finding",
        ),
        (
            {
                "mapping": {"name": "x1", "source": "s"},
                "emit": [{"node": {"type": "Asset", "identifiers": {"fqdn": {"path": "$.a", "transform": "rot13"}}}}],
            },
            "unknown transform",
        ),
        ({"mapping": {"name": "x1", "source": "s", "surprise": 1}, "emit": []}, "invalid mapping"),
        ({"mapping": {"name": "Bad Name", "source": "s"}, "emit": []}, "snake_case"),
    ],
)
def test_mappings_are_validated_against_the_ontology_at_load(ontology, bad, message):
    with pytest.raises(ConfigurationError) as excinfo:
        Mapping(bad, ontology, "test.yaml")
    assert message in excinfo.value.message


# ---- shipped mappings -------------------------------------------------------
def test_assets_csv(db, tenant, run, find):
    out = run("assets_csv", read_source("assets.csv"))
    assert out["source_records"] == 16 and out["quarantined_total"] == 0
    assert out["nodes"]["created"] == 16 + 4 + 5  # assets, segments, business services
    web = find("web-portal-01.dmz.meridian.example", "Asset", "fqdn")
    assert web["name"] == "web-portal-01"
    assert web["properties"] == {
        "asset_type": "server",
        "os": "Ubuntu",
        "os_version": "22.04",
        "environment": "production",
        "criticality": 4,
        "crown_jewel": False,
        "internet_exposed": True,
        "owner": "Digital Channels",
        "location": "BLR-DC1",
        "status": "active",
    }
    assert web["identifiers"]["ip"] == ["10.10.1.10", "203.0.113.10"]
    assert web["identifiers"]["serial"] == ["VMW-7F3A1001"] and web["identifiers"]["asset_id"] == ["ci-1001"]
    assert neighbours(db, tenant, web["id"], "IN_SEGMENT") == ["dmz"]
    assert neighbours(db, tenant, web["id"], "SUPPORTS") == ["Internet Banking"]
    vpn = find("CI-1003", "Asset", "asset_id")
    assert neighbours(db, tenant, vpn["id"], "SUPPORTS") == []  # no business service in that row
    again = run("assets_csv", read_source("assets.csv"))
    assert again["nodes"]["created"] == 0 and again["nodes"]["updated"] == 0 and again["edges"]["created"] == 0


def test_identities_csv_with_group_membership(db, tenant, run, find):
    out = run("identities_csv", read_source("identities.csv"))
    assert out["quarantined_total"] == 0
    admin = find("corp\\asharma", "Identity", "account")
    assert admin["properties"]["privileged"] is True and admin["properties"]["identity_type"] == "human"
    assert admin["identifiers"]["upn"] == ["anita.sharma@meridian.example"]
    assert neighbours(db, tenant, admin["id"], "MEMBER_OF") == ["corp\\domain admins"]
    group = find("corp\\cbs operators", "Identity", "account")
    assert group["properties"]["identity_type"] == "group"
    assert neighbours(db, tenant, group["id"], "MEMBER_OF", "in") == ["Karthik Iyer", "UPI switch service account"]
    service = find("corp\\svc-ib-app", "Identity", "account")
    assert "upn" not in service["identifiers"] and neighbours(db, tenant, service["id"], "MEMBER_OF") == []


def test_reference_feeds_merge_into_one_vulnerability(run, find):
    nvd = run("nvd_cve", read_source("nvd_cves.json"))
    assert nvd["nodes"]["created"] == 11 and nvd["quarantined_total"] == 0
    cve = find("CVE-2021-44228", "Vulnerability", "cve")
    assert cve["properties"]["cvss_score"] == 10.0
    assert cve["properties"]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cve["properties"]["attack_vector"] == "network"
    assert cve["properties"]["cwe"] == ["CWE-20", "CWE-400", "CWE-502"]
    assert cve["properties"]["description"].startswith("Apache Log4j2 JNDI")  # the English description
    assert cve["properties"]["published"] == "2021-12-10T10:15:09Z"
    assert cve["properties"]["kev"] is True and cve["properties"]["kev_date_added"] == "2021-12-10T00:00:00Z"
    local = find("CVE-2021-3156", "Vulnerability", "cve")
    assert local["properties"]["attack_vector"] == "local"
    not_kev = find("CVE-2024-6387", "Vulnerability", "cve")
    assert "kev" not in not_kev["properties"]

    kev = run("cisa_kev", read_source("kev.json"))
    assert kev["nodes"]["updated"] == 8 and kev["nodes"]["created"] == 0
    cve = find("CVE-2021-44228", "Vulnerability", "cve")
    assert cve["properties"]["ransomware_use"] is True and cve["properties"]["exploit_available"] is True
    assert cve["properties"]["title"] == "Apache Log4j2 Remote Code Execution Vulnerability"
    assert find("CVE-2022-22965", "Vulnerability", "cve")["properties"]["ransomware_use"] is False

    epss = run("epss_csv", read_source("epss.csv"))
    assert epss["source_records"] == 11 and epss["nodes"]["updated"] == 11
    cve = find("CVE-2021-44228", "Vulnerability", "cve")
    assert cve["properties"]["epss"] == 0.94358 and cve["properties"]["epss_percentile"] == 0.99957
    assert set(cve["sources"]) == {"nvd", "kev", "epss"}


def test_scanner_findings_csv(db, tenant, run, find):
    run("assets_csv", read_source("assets.csv"))
    out = run("vuln_findings_csv", read_source("scanner_findings.csv"))
    assert out["source_records"] == 15 and out["quarantined_total"] == 0
    assert out["nodes"]["created"] == 15  # findings; the assets already exist and are only referenced
    assert out["stubs_created"] == 11  # vulnerabilities not loaded yet: stubs keep the edges
    key = "vm-scanner:vpn-gw-01.dmz.meridian.example:CVE-2024-3400:443"
    finding = find(key, "Finding", "finding_key")
    assert finding["properties"]["status"] == "risk_accepted" and finding["properties"]["port"] == 443
    assert finding["properties"]["due_date"] == "2026-07-14T00:00:00Z"
    assert neighbours(db, tenant, finding["id"], "INSTANCE_OF") == ["CVE-2024-3400"]
    assert neighbours(db, tenant, finding["id"], "HAS_FINDING", "in") == ["vpn-gw-01"]
    fixed = find("vm-scanner:jump-01.mgmt.meridian.example:CVE-2024-6387:22", "Finding", "finding_key")
    assert fixed["properties"]["status"] == "resolved"
    local = find("vm-scanner:cbs-db-01.restricted.meridian.example:CVE-2021-3156:0", "Finding", "finding_key")
    assert "port" not in local["properties"]
    # the stub CVE becomes a full record when the feed arrives, keeping its id and edges
    stub = find("CVE-2024-3400", "Vulnerability", "cve")
    assert stub["stub"] is True
    run("nvd_cve", read_source("nvd_cves.json"))
    full = find("CVE-2024-3400", "Vulnerability", "cve")
    assert full["id"] == stub["id"] and full["stub"] is False and full["properties"]["cvss_score"] == 10.0


def test_cyclonedx_sbom(db, tenant, run, find):
    with pytest.raises(ValidationFailed):
        run("cyclonedx", read_source("web-portal-01.cdx.json"), params={"nope": "x"})
    out = run(
        "cyclonedx", read_source("web-portal-01.cdx.json"), params={"asset_fqdn": "web-portal-01.dmz.meridian.example"}
    )
    assert out["source_records"] == 6 and out["nodes"]["created"] == 5 and out["quarantined_total"] == 0
    asset = find("web-portal-01.dmz.meridian.example", "Asset", "fqdn")
    assert neighbours(db, tenant, asset["id"], "RUNS") == [
        "commons-text",
        "jackson-databind",
        "log4j-core",
        "nginx",
        "spring-webmvc",
    ]
    log4j = find("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "Software", "purl")
    assert log4j["properties"] == {
        "name": "log4j-core",
        "version": "2.14.1",
        "vendor": "org.apache.logging.log4j",
        "ecosystem": "library",
        "license": "Apache-2.0",
    }
    nginx = find("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "Software", "cpe")
    assert nginx["properties"]["version"] == "1.18.0"


def test_sbom_attaches_to_the_inventory_asset_without_creating_a_duplicate(db, tenant, run, find):
    run("assets_csv", read_source("assets.csv"))
    by_parameter = run(
        "cyclonedx", read_source("web-portal-01.cdx.json"), params={"asset_fqdn": "web-portal-01.dmz.meridian.example"}
    )
    assert by_parameter["conflicts"] == 0 and by_parameter["stubs_created"] == 0
    # with no parameter the SBOM's component name is used as a host name and still lands on the same asset
    by_name = run("cyclonedx", read_source("web-portal-01.cdx.json"))
    assert by_name["conflicts"] == 0 and by_name["stubs_created"] == 0 and by_name["edges"]["created"] == 0
    asset = find("CI-1001", "Asset", "asset_id")
    assert len(neighbours(db, tenant, asset["id"], "RUNS")) == 5
    with db.transaction() as s:
        assert GraphReader(s, tenant).count_nodes_by_type()["Asset"] == 16


def test_attack_stix_bundle(db, tenant, run, find):
    out = run("attack_stix", read_source("attack.stix.json"))
    assert out["quarantined_total"] == 0
    assert out["nodes"]["created"] == 8 + 2  # techniques (the revoked one is skipped) and groups
    technique = find("T1190", "Technique", "attack_id")
    assert technique["name"] == "Exploit Public-Facing Application"
    assert technique["properties"]["tactics"] == ["initial-access"]
    assert technique["identifiers"]["stix_id"] == ["attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"]
    sub = find("t1003.006", "Technique", "attack_id")
    assert sub["name"] == "DCSync"
    actor = find("apt41", "ThreatActor", "actor_key")
    assert actor["properties"]["aliases"] == ["APT41", "Wicked Panda", "Brass Typhoon"]
    assert neighbours(db, tenant, actor["id"], "USES") == [
        "Command and Scripting Interpreter",
        "Exploit Public-Facing Application",
        "Exploitation of Remote Services",
        "Valid Accounts",
    ]
    assert out["edges"]["created"] == 6  # malware→technique and subtechnique-of relationships are not 'uses by a group'
    assert out["stubs_created"] == 0
    with db.transaction() as s:
        assert "T1999" not in [n.name for n in GraphReader(s, tenant).search_nodes(types=["Technique"])[0]]


def test_ocsf_vulnerability_findings_merge_with_inventory_by_hostname(db, tenant, run, find):
    run("assets_csv", read_source("assets.csv"))
    out = run("ocsf_vulnerability_finding", read_source("ocsf_vulnerability_findings.json"))
    assert out["quarantined_total"] == 0 and out["source_records"] == 2
    assert out["nodes"]["created"] == 3 + 2  # three findings, two CVEs (one shared by both hosts)
    host = find("hr-ws-114.core.meridian.example", "Asset", "fqdn")
    assert host["identifiers"]["agent_id"] == ["edr-agent-5f2c0114"]  # EDR record merged into the CMDB asset
    assert set(host["sources"]) == {"cmdb", "ocsf"}
    assert len(neighbours(db, tenant, host["id"], "HAS_FINDING")) == 2
    finding = find("edr-sensor:vf-7001:CVE-2019-0708", "Finding", "finding_key")
    assert finding["properties"]["severity"] == "critical" and finding["properties"]["status"] == "open"
    assert finding["properties"]["scanner"] == "edr-sensor"
    in_progress = find("edr-sensor:vf-7002:CVE-2021-34527", "Finding", "finding_key")
    assert in_progress["properties"]["status"] == "in_progress"
    cve = find("CVE-2019-0708", "Vulnerability", "cve")
    assert cve["properties"] == {
        "cvss_score": 9.8,
        "epss": 0.94453,
        "kev": True,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    shared = find("CVE-2021-34527", "Vulnerability", "cve")
    assert len(neighbours(db, tenant, shared["id"], "INSTANCE_OF", "in")) == 2


def test_ocsf_detections(db, tenant, run, find):
    run("assets_csv", read_source("assets.csv"))
    run("identities_csv", read_source("identities.csv"))
    run("attack_stix", read_source("attack.stix.json"))
    out = run("ocsf_detection_finding", read_source("ocsf_detections.json"))
    assert out["quarantined_total"] == 0 and out["source_records"] == 4
    assert out["nodes"]["created"] == 4 + 1  # alerts and one indicator (seen twice); the process name is ignored
    alert = find("sovereign-siem:det-9001", "Alert", "alert_key")
    assert alert["properties"]["severity"] == "high" and alert["properties"]["status"] == "new"
    assert alert["properties"]["rule"] == "Log4Shell exploitation attempt"
    assert alert["properties"]["event_time"].startswith("2026-09-")
    assert neighbours(db, tenant, alert["id"], "TRIGGERED_ON") == ["web-portal-01"]
    assert neighbours(db, tenant, alert["id"], "INDICATES") == ["Exploit Public-Facing Application"]
    assert neighbours(db, tenant, alert["id"], "OBSERVED") == ["198.51.100.77"]
    indicator = find("198.51.100.77", "Indicator", "indicator")
    assert indicator["properties"] == {"indicator_type": "ip", "reputation": "malicious"}
    assert len(neighbours(db, tenant, indicator["id"], "OBSERVED", "in")) == 2
    dcsync = find("sovereign-siem:det-9003", "Alert", "alert_key")
    assert neighbours(db, tenant, dcsync["id"], "INDICATES") == ["DCSync"]  # the sub-technique wins
    assert neighbours(db, tenant, dcsync["id"], "TRIGGERED_ON") == ["Internet Banking service account", "ad-dc-01"]
    rdp = find("sovereign-siem:det-9004", "Alert", "alert_key")
    assert rdp["properties"]["status"] == "closed"
    assert out["stubs_created"] == 0


# ---- robustness -------------------------------------------------------------
def test_bad_source_records_are_quarantined_and_the_rest_loads(db, tenant, run):
    payload = "fqdn,criticality,ip\ngood.corp.example,3,10.0.0.1\n,4,\nbad.corp.example,eleven,10.0.0.2\n"
    out = run("assets_csv", payload)
    assert out["source_records"] == 3
    assert out["nodes"]["created"] == 2  # 'eleven' is not a number: the transform yields nothing, the asset still loads
    assert out["quarantined_total"] == 1 and "identifier" in out["quarantined"][0]["reason"]
    with db.transaction() as s:
        rows = s.execute(select(QuarantinedRecord).where(QuarantinedRecord.tenant_id == tenant)).scalars().all()
        assert len(rows) == 1 and rows[0].source == "cmdb"


def test_malformed_payloads_are_rejected_cleanly(run):
    with pytest.raises(ValidationFailed, match="not valid JSON"):
        run("nvd_cve", "{not json")
    with pytest.raises(ValidationFailed, match="no header row"):
        run("assets_csv", "")
    with pytest.raises(ValidationFailed, match="did not select a list"):
        run("nvd_cve", json.dumps({"vulnerabilities": "nope"}))
    with pytest.raises(ValidationFailed, match="UTF-8"):
        run("assets_csv", b"\xff\xfe\x00bad")
    assert run("nvd_cve", json.dumps({"vulnerabilities": []}))["source_records"] == 0
    with pytest.raises(ValidationFailed, match="source must be"):
        run("assets_csv", "fqdn\na.b.example\n", source="Bad Source!")


def test_large_files_are_split_into_batches(ingest_service, registry, tenant, db):
    from tests.conftest import make_settings

    small = make_settings(db.settings.database_url, ingest_max_records=8)
    rows = "\n".join(f"h{i}.corp.example,{i % 5 + 1}" for i in range(20))
    out = ingest_source(ingest_service, registry, small, tenant, "user:test", "assets_csv", "fqdn,criticality\n" + rows)
    assert out["nodes"]["created"] == 20 and len(out["batches"]) == 5


def test_site_mappings_directory_and_the_documented_example(ingest_service, ontology, settings, tenant, db, find):
    """config/mappings is the worked example in docs/DATA_ONBOARDING.md; it has to load and behave as described."""
    from pathlib import Path

    directory = Path(__file__).resolve().parents[1] / "config" / "mappings"
    registry = MappingRegistry(ontology, str(directory))
    assert "example_cmdb" in registry.names() and "assets_csv" in registry.names()
    payload = json.dumps(
        {
            "result": [
                {
                    "sys_id": "SYS0001",
                    "fqdn": "erp-01.corp.example",
                    "ip_address": "10.20.0.5, 10.20.1.5",
                    "name": "erp-01",
                    "os": "RHEL",
                    "used_for": "Production",
                    "business_criticality": "4",
                    "owned_by": {"display_value": ""},
                    "support_group": {"display_value": "ERP Operations"},
                    "business_service": "Finance ERP",
                },
                {"sys_id": "SYS0002", "fqdn": "lab-07.corp.example"},
                {"sys_id": "SYS0003", "fqdn": "box-09.corp.example", "used_for": "Sandbox"},
            ]
        }
    )
    out = ingest_source(ingest_service, registry, settings, tenant, "user:test", "example_cmdb", payload)
    assert out["source_records"] == 3
    # A value the map does not list is passed through, and the ontology then refuses it by name.
    assert [q["reason"] for q in out["quarantined"]] == [
        "Asset.environment: 'Sandbox' is not one of production, staging, development, test, dr, unknown"
    ]
    erp = find("SYS0001", "Asset")
    assert erp["properties"]["environment"] == "production" and erp["properties"]["criticality"] == 4
    assert erp["properties"]["owner"] == "ERP Operations"  # coalesce skipped the empty first choice
    assert sorted(erp["identifiers"]["ip"]) == ["10.20.0.5", "10.20.1.5"]
    assert neighbours(db, tenant, erp["id"], "SUPPORTS") == ["Finance ERP"]
    lab = find("lab-07.corp.example", "Asset", "fqdn")
    assert lab["properties"]["environment"] == "unknown"  # field absent -> default
    assert neighbours(db, tenant, lab["id"], "SUPPORTS") == []  # no business_service -> no edge

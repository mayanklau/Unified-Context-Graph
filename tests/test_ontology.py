"""The ontology: loading, integrity checks, normalisation, coercion, and the generated reference."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from secgraph.errors import OntologyError, ValidationFailed
from secgraph.ontology import load_ontology, parse_ontology
from secgraph.ontology.docs import render_markdown
from secgraph.ontology.normalize import normalize_identifier
from secgraph.ontology.validate import (
    coerce_properties,
    format_datetime,
    matches,
    normalize_identifiers,
    parse_datetime,
)

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def document():
    path = REPO / "secgraph" / "ontology" / "core.ontology.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_core_ontology_loads(ontology):
    assert ontology.name == "security-graph-core" and ontology.version == "1.0.0"
    assert {"Asset", "Identity", "Finding", "Vulnerability", "Control", "AIAgent"} <= set(ontology.node_types)
    assert len(ontology.fingerprint()) == 64
    assert ontology.sensitive_properties() == {"Identity": frozenset({"display_name"})}
    assert ontology.sensitive_identifiers() == {"Identity": frozenset({"upn", "email"})}


def test_fingerprint_changes_with_content(document, ontology):
    changed = copy.deepcopy(document)
    changed["attack_semantics"]["exploitability"]["kev_floor"] = 0.8
    assert parse_ontology(changed).fingerprint() != ontology.fingerprint()
    assert parse_ontology(copy.deepcopy(document)).fingerprint() == ontology.fingerprint()


def _broken(document, mutate):
    changed = copy.deepcopy(document)
    mutate(changed)
    with pytest.raises(OntologyError) as excinfo:
        parse_ontology(changed, origin="test.yaml")
    return " ".join(excinfo.value.detail.get("errors", [])) + excinfo.value.message


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d["edge_types"]["RUNS"].__setitem__("target", ["Nope"]), "unknown node type 'Nope'"),
        (lambda d: d["ontology"].__setitem__("version", "one"), "semantic"),
        (lambda d: d["node_types"].__setitem__("bad_name", d["node_types"]["Asset"]), "PascalCase"),
        (lambda d: d["edge_types"].__setitem__("badEdge", d["edge_types"]["RUNS"]), "UPPER_SNAKE_CASE"),
        (lambda d: d["node_types"]["Asset"].__setitem__("identifiers", []), "at least one identifier"),
        (lambda d: d["node_types"]["Finding"]["identifiers"][0].__setitem__("weak", True), "strong, matchable"),
        (lambda d: d["node_types"]["Asset"]["properties"].__setitem__("BadProp", {"type": "string"}), "snake_case"),
        (lambda d: d["node_types"]["Asset"]["properties"].__setitem__("x", {"type": "enum"}), "enum properties"),
        (lambda d: d["node_types"]["Asset"].__setitem__("surprise", 1), "Extra inputs"),
        (lambda d: d["attack_semantics"]["transitions"][0].__setitem__("edge", "NOPE"), "unknown edge type 'NOPE'"),
        (lambda d: d["attack_semantics"]["transitions"][0]["probability"].__setitem__("value", 1.5), "within [0, 1]"),
        (
            lambda d: d["attack_semantics"]["transitions"].append(dict(d["attack_semantics"]["transitions"][0])),
            "duplicate transition",
        ),
        (lambda d: d["attack_semantics"]["compromisable"].append("Ghost"), "unknown node type 'Ghost'"),
        (lambda d: d["attack_semantics"]["targets"][0].__setitem__("node_type", "Finding"), "not compromisable"),
        (lambda d: d["attack_semantics"]["entries"][0].__setitem__("where", {"x": {"bogus": 1}}), "invalid predicate"),
        (lambda d: d["attack_semantics"]["bindings"].__setitem__("protects_edge", "NOPE"), "unknown edge type"),
        (lambda d: d["node_types"]["Asset"].__setitem__("name_from", ["ghost"]), "name_from references unknown"),
        (
            lambda d: d["node_types"]["Asset"]["identifiers"][6].__setitem__("derived_from", "ghost"),
            "derives from unknown",
        ),
    ],
)
def test_invalid_ontologies_are_rejected_with_a_reason(document, mutate, expected):
    assert expected in _broken(document, mutate)


def test_load_errors(tmp_path):
    with pytest.raises(OntologyError, match="not found"):
        load_ontology(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(OntologyError, match="not valid YAML"):
        load_ontology(bad)
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(OntologyError, match="must be a YAML mapping"):
        load_ontology(bad)


def test_custom_ontology_file(tmp_path, document):
    custom = copy.deepcopy(document)
    custom["ontology"]["version"] = "1.1.0"
    custom["node_types"]["Asset"]["properties"]["cost_centre"] = {"type": "string"}
    path = tmp_path / "custom.ontology.yaml"
    path.write_text(yaml.safe_dump(custom), encoding="utf-8")
    loaded = load_ontology(path)
    assert loaded.version == "1.1.0" and "cost_centre" in loaded.node_types["Asset"].properties


# ---- normalisation ----------------------------------------------------------
@pytest.mark.parametrize(
    "normalizer, raw, expected",
    [
        ("fqdn", "WEB-01.Corp.Example.", "web-01.corp.example"),
        ("hostname", "WEB-01", "web-01"),
        ("hostname", "web-01.corp.example", "web-01"),
        ("mac", "00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("mac", "001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("ip", "010.0.0.1", None),
        ("ip", "10.0.0.1", "10.0.0.1"),
        ("ip", "2001:DB8::1", "2001:db8::1"),
        ("cidr", "10.1.2.3/24", "10.1.2.0/24"),
        ("cve", "cve-2021-44228", "CVE-2021-44228"),
        ("attack_id", "t1059.001", "T1059.001"),
        ("attack_id", "aml.t0051", "AML.T0051"),
        ("email", "Asha.Rao@Example.COM", "asha.rao@example.com"),
        ("purl", "PKG:Maven/org.apache/log4j-core@2.14.1", "pkg:maven/org.apache/log4j-core@2.14.1"),
        ("cpe", "CPE:2.3:a:F5:nginx:1.18.0", "cpe:2.3:a:f5:nginx:1.18.0"),
        ("upper", "sn-1", "SN-1"),
        ("none", " Keep Case ", "Keep Case"),
    ],
)
def test_identifier_normalisation(normalizer, raw, expected):
    if expected is None:
        with pytest.raises(ValidationFailed):
            normalize_identifier(normalizer, "k", raw)
    else:
        assert normalize_identifier(normalizer, "k", raw) == expected


@pytest.mark.parametrize(
    "normalizer, raw",
    [
        ("fqdn", "nodots"),
        ("fqdn", "bad host.example"),
        ("mac", "zz:zz"),
        ("cve", "CVE-21-1"),
        ("attack_id", "X9"),
        ("email", "no-at-sign"),
        ("email", "a@b@c"),
        ("purl", "maven/x"),
        ("cpe", "x"),
        ("lower", ""),
        ("lower", "   "),
        ("lower", "a\x00b"),
        ("lower", "x" * 600),
        ("lower", True),
        ("lower", ["a"]),
        ("hostname", "-bad-"),
        ("cidr", "10.0.0.0/99"),
    ],
)
def test_invalid_identifiers_are_rejected(normalizer, raw):
    with pytest.raises(ValidationFailed):
        normalize_identifier(normalizer, "k", raw)


def test_identifier_sets(ontology):
    asset = ontology.node_types["Asset"]
    pairs = normalize_identifiers(
        "Asset", asset, {"ip": ["10.0.0.2", "10.0.0.1", "10.0.0.2"], "fqdn": "A.corp.example"}
    )
    assert pairs == [("fqdn", "a.corp.example"), ("hostname", "a"), ("ip", "10.0.0.2"), ("ip", "10.0.0.1")]
    explicit = normalize_identifiers("Asset", asset, {"fqdn": "a.corp.example", "hostname": "alias"})
    assert ("hostname", "alias") in explicit and ("hostname", "a") not in explicit  # given beats derived
    for bad, reason in [
        ({}, "at least one identifier"),
        ({"nope": "x"}, "unknown identifier 'nope'"),
        ({"serial": ["A", "B"]}, "exclusive identifier given 2"),
        ({"ip": "10.0.0.1"}, "can identify an entity"),
        ({"fqdn": None}, "at least one identifier"),
        ({"mac": ["x"] * 70}, "more than 64"),
    ]:
        with pytest.raises(ValidationFailed) as excinfo:
            normalize_identifiers("Asset", asset, bad)
        assert reason in excinfo.value.message


# ---- property coercion ------------------------------------------------------
def coerce(ontology, node_type, properties, **kwargs):
    definition = ontology.node_types[node_type]
    return coerce_properties(
        node_type,
        definition.properties,
        definition.additional_properties,
        properties,
        enforce_required=kwargs.get("enforce_required", False),
        max_bytes=kwargs.get("max_bytes", 65536),
    )


def test_coercion_of_messy_but_unambiguous_values(ontology):
    assert coerce(
        ontology,
        "Asset",
        {
            "criticality": "4",
            "internet_exposed": "Yes",
            "crown_jewel": 0,
            "environment": "Production",
            "os": 22,
            "custom.tag": ["a"],
            "owner": None,
        },
    ) == {
        "criticality": 4,
        "internet_exposed": True,
        "crown_jewel": False,
        "environment": "production",
        "os": "22",
        "custom.tag": ["a"],
        "owner": None,
    }
    vuln = coerce(
        ontology,
        "Vulnerability",
        {"cvss_score": "9.8", "cwe": "CWE-79, CWE-89,CWE-79", "published": "2024-03-01", "kev_date_added": 1700000000},
    )
    assert vuln == {
        "cvss_score": 9.8,
        "cwe": ["CWE-79", "CWE-89"],
        "published": "2024-03-01T00:00:00Z",
        "kev_date_added": "2023-11-14T22:13:20Z",
    }
    assert coerce(ontology, "Finding", {"status": "Risk Accepted", "severity": "HIGH"}) == {
        "status": "risk_accepted",
        "severity": "high",
    }


@pytest.mark.parametrize(
    "node_type, properties, reason",
    [
        ("Asset", {"criticality": 9}, "above the maximum 5"),
        ("Asset", {"criticality": 0}, "below the minimum 1"),
        ("Asset", {"criticality": 2.5}, "whole number"),
        ("Asset", {"criticality": "many"}, "expected a number"),
        ("Asset", {"criticality": True}, "expected a number"),
        ("Asset", {"internet_exposed": "maybe"}, "expected true or false"),
        ("Asset", {"environment": "moon"}, "is not one of"),
        ("Asset", {"os": {"nested": 1}}, "expected a string"),
        ("Asset", {"name": "x" * 300}, "longer than 256"),
        ("Asset", {"bad name!": 1}, "property names"),
        ("Vulnerability", {"published": "yesterday"}, "unrecognised timestamp"),
        ("Vulnerability", {"cwe": [{"a": 1}]}, "list of strings"),
        ("Vulnerability", {"cvss_score": float("nan")}, "finite"),
        ("Vulnerability", {"epss": 1.2}, "above the maximum 1"),
    ],
)
def test_coercion_rejects_with_a_precise_reason(ontology, node_type, properties, reason):
    with pytest.raises(ValidationFailed) as excinfo:
        coerce(ontology, node_type, properties)
    assert reason in excinfo.value.message


def test_required_and_size_limits(ontology):
    with pytest.raises(ValidationFailed, match="control_type: required"):
        coerce(ontology, "Control", {"name": "x"}, enforce_required=True)
    assert coerce(ontology, "Control", {"name": "x"}) == {"name": "x"}
    with pytest.raises(ValidationFailed, match="byte limit"):
        coerce(ontology, "Asset", {"notes": "x" * 3000}, max_bytes=1000)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-09-30T10:00:00Z", "2026-09-30T10:00:00Z"),
        ("2026-09-30T15:30:00+05:30", "2026-09-30T10:00:00Z"),
        ("2026-09-30 10:00:00", "2026-09-30T10:00:00Z"),
        ("30/09/2026", "2026-09-30T00:00:00Z"),
        (1790000000, "2026-09-21T14:13:20Z"),
        (1790000000000, "2026-09-21T14:13:20Z"),
        (datetime(2026, 1, 1, tzinfo=UTC), "2026-01-01T00:00:00Z"),
    ],
)
def test_timestamps(value, expected):
    assert format_datetime(parse_datetime(value)) == expected


@pytest.mark.parametrize("value", ["", "not a date", True, -5, float("inf"), [2026]])
def test_bad_timestamps(value):
    with pytest.raises(ValueError):
        parse_datetime(value)


def test_predicates():
    props = {"zone": "dmz", "criticality": 4, "tags": ["pci", "core"], "name": "Web Portal", "flag": True}
    assert matches(props, {"zone": "dmz", "criticality": {"gte": 4, "lt": 5}})
    assert matches(props, {"tags": {"contains": "pci"}, "name": {"contains": "portal"}})
    assert matches(props, {"zone": {"in": ["dmz", "internal"]}, "owner": {"exists": False}, "flag": True})
    assert matches(props, {"zone": {"ne": "internal", "nin": ["restricted"]}})
    assert not matches(props, {"criticality": {"gt": 4}})
    assert not matches(props, {"missing": {"gte": 1}})
    assert not matches(props, {"name": {"gt": 5}})  # incomparable types are simply not a match
    assert not matches(props, {"zone": "internal"})


# ---- generated reference ----------------------------------------------------
def test_reference_document_is_in_sync_with_the_ontology(ontology):
    rendered = render_markdown(ontology)
    assert "### Asset" in rendered and "| `lateral_exploit` |" in rendered and ontology.fingerprint() in rendered
    committed = REPO / "docs" / "ONTOLOGY.md"
    assert committed.is_file(), "run: secgraph ontology docs > docs/ONTOLOGY.md"
    assert committed.read_text(encoding="utf-8") == rendered, (
        "docs/ONTOLOGY.md is stale; regenerate with: secgraph ontology docs > docs/ONTOLOGY.md"
    )

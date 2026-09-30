"""Query service: lookup, search, neighbourhood, subgraph, shortest path, pattern matching, masking."""

from __future__ import annotations

import random
from collections import deque
from datetime import UTC, datetime

import pytest

from secgraph.errors import NotFound, PermissionDenied, ValidationFailed
from secgraph.governance.rbac import FULL_SCOPE, AccessScope
from secgraph.query.service import QueryService


@pytest.fixture()
def query(ontology, settings):
    return QueryService(ontology, settings)


@pytest.fixture()
def estate(load):
    """A small estate: two assets, software, a KEV finding, an identity with access."""
    result = load(
        nodes=[
            {"type": "Asset", "identifiers": {"fqdn": "web-01.dmz.example", "ip": "203.0.113.10"},
             "properties": {"internet_exposed": True, "criticality": 3, "environment": "production"}, "ref": "web"},
            {"type": "Asset", "identifiers": {"fqdn": "db-01.core.example"},
             "properties": {"criticality": 5, "crown_jewel": True}, "ref": "db"},
            {"type": "Software", "identifiers": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
             "properties": {"name": "log4j-core", "version": "2.14.1"}, "ref": "sw"},
            {"type": "Vulnerability", "identifiers": {"cve": "CVE-2021-44228"},
             "properties": {"cvss_score": 10.0, "kev": True, "epss": 0.97, "cwe": ["CWE-502", "CWE-917"]},
             "ref": "cve"},
            {"type": "Finding", "identifiers": {"finding_key": "scan:web-01:CVE-2021-44228"},
             "properties": {"status": "open", "severity": "critical"}, "ref": "f"},
            {"type": "Finding", "identifiers": {"finding_key": "scan:db-01:old"},
             "properties": {"status": "resolved", "severity": "low"}, "ref": "f2"},
            {"type": "Identity", "identifiers": {"upn": "asha.rao@example.com", "account": "corp\\arao"},
             "properties": {"display_name": "Asha Rao", "identity_type": "human", "privileged": True}, "ref": "id"},
        ],
        edges=[
            {"type": "RUNS", "source": {"ref": "web"}, "target": {"ref": "sw"}},
            {"type": "HAS_FINDING", "source": {"ref": "web"}, "target": {"ref": "f"}},
            {"type": "HAS_FINDING", "source": {"ref": "db"}, "target": {"ref": "f2"}},
            {"type": "INSTANCE_OF", "source": {"ref": "f"}, "target": {"ref": "cve"}},
            {"type": "AFFECTS", "source": {"ref": "cve"}, "target": {"ref": "sw"}},
            {"type": "CONNECTS_TO", "source": {"ref": "web"}, "target": {"ref": "db"}, "key": "tcp/5432",
             "properties": {"port": 5432, "protocol": "tcp"}},
            {"type": "HAS_ACCESS", "source": {"ref": "id"}, "target": {"ref": "db"}, "properties": {"privilege": "admin"}},
        ],
    )
    assert not result.rejections
    return result.refs


def test_get_node_includes_identifiers_and_degree(db, tenant, query, estate):
    with db.transaction() as s:
        node = query.get_node(s, tenant, estate["web"], FULL_SCOPE)
    assert node["name"] == "web-01"
    assert node["identifiers"] == {"fqdn": ["web-01.dmz.example"], "hostname": ["web-01"], "ip": ["203.0.113.10"]}
    assert node["degree"]["CONNECTS_TO"] == {"out": 1, "in": 0}
    assert node["properties"]["internet_exposed"] is True
    with db.transaction() as s, pytest.raises(NotFound):
        query.get_node(s, tenant, "f" * 32, FULL_SCOPE)


def test_find_by_identifier_normalises(db, tenant, query, estate):
    with db.transaction() as s:
        by_ip = query.find_by_identifier(s, tenant, FULL_SCOPE, value="203.0.113.10")
        by_fqdn = query.find_by_identifier(s, tenant, FULL_SCOPE, value="WEB-01.DMZ.EXAMPLE.", node_type="Asset",
                                           kind="fqdn")
        by_cve = query.find_by_identifier(s, tenant, FULL_SCOPE, value="cve-2021-44228", node_type="Vulnerability",
                                          kind="cve")
        nothing = query.find_by_identifier(s, tenant, FULL_SCOPE, value="no-such-thing")
    assert [n["id"] for n in by_ip] == [estate["web"]]
    assert [n["id"] for n in by_fqdn] == [estate["web"]]
    assert [n["id"] for n in by_cve] == [estate["cve"]]
    assert nothing == []


def test_search_text_types_and_property_filters(db, tenant, query, estate):
    with db.transaction() as s:
        assert [n["id"] for n in query.search(s, tenant, FULL_SCOPE, types=["Asset"], text="WEB-0")["items"]] == [
            estate["web"]]
        assert query.search(s, tenant, FULL_SCOPE, text="WEB-0")["total"] == 2  # the finding's key matches too
        assets = query.search(s, tenant, FULL_SCOPE, types=["Asset"])
        assert assets["total"] == 2
        exposed = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"internet_exposed": True})
        assert [n["id"] for n in exposed["items"]] == [estate["web"]]
        critical = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"criticality": {"gte": 4}})
        assert [n["id"] for n in critical["items"]] == [estate["db"]]
        between = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"criticality": {"gt": 2, "lt": 5}})
        assert [n["id"] for n in between["items"]] == [estate["web"]]
        open_findings = query.search(s, tenant, FULL_SCOPE, types=["Finding"],
                                     where={"status": {"in": ["open", "in_progress"]}})
        assert [n["id"] for n in open_findings["items"]] == [estate["f"]]
        not_open = query.search(s, tenant, FULL_SCOPE, types=["Finding"], where={"status": {"ne": "open"}})
        assert [n["id"] for n in not_open["items"]] == [estate["f2"]]
        by_cwe = query.search(s, tenant, FULL_SCOPE, types=["Vulnerability"], where={"cwe": {"contains": "CWE-502"}})
        assert [n["id"] for n in by_cwe["items"]] == [estate["cve"]]
        by_substring = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"environment": {"contains": "PROD"}})
        assert [n["id"] for n in by_substring["items"]] == [estate["web"]]
        has_flag = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"crown_jewel": {"exists": True}})
        assert [n["id"] for n in has_flag["items"]] == [estate["db"]]
        no_flag = query.search(s, tenant, FULL_SCOPE, types=["Asset"], where={"crown_jewel": {"exists": False}})
        assert [n["id"] for n in no_flag["items"]] == [estate["web"]]
        paged = query.search(s, tenant, FULL_SCOPE, limit=2, offset=2)
        assert paged["total"] == 7 and len(paged["items"]) == 2


def test_search_rejects_bad_input(db, tenant, query, estate):
    with db.transaction() as s:
        with pytest.raises(ValidationFailed):
            query.search(s, tenant, FULL_SCOPE, types=["Nope"])
        with pytest.raises(ValidationFailed):
            query.search(s, tenant, FULL_SCOPE, where={"criticality": {"weird": 1}})
        with pytest.raises(ValidationFailed):
            query.search(s, tenant, FULL_SCOPE, where={"bad key; drop table": 1})
        with pytest.raises(ValidationFailed):
            query.search(s, tenant, FULL_SCOPE, limit=0)
        # a hostile value is just a value
        assert query.search(s, tenant, FULL_SCOPE, text="%' OR 1=1 --")["total"] == 0
        assert query.search(s, tenant, FULL_SCOPE, where={"os": "x' OR '1'='1"})["total"] == 0


def test_neighbors_direction_and_filters(db, tenant, query, estate):
    with db.transaction() as s:
        out = query.neighbors(s, tenant, estate["web"], FULL_SCOPE, direction="out")
        assert sorted(n["edge"]["type"] for n in out["neighbors"]) == ["CONNECTS_TO", "HAS_FINDING", "RUNS"]
        assert all(n["direction"] == "out" for n in out["neighbors"])
        inbound = query.neighbors(s, tenant, estate["db"], FULL_SCOPE, direction="in")
        assert sorted(n["node"]["type"] for n in inbound["neighbors"]) == ["Asset", "Identity"]
        only = query.neighbors(s, tenant, estate["db"], FULL_SCOPE, edge_types=["HAS_ACCESS"])
        assert [n["node"]["name"] for n in only["neighbors"]] == ["Asha Rao"]
        limited = query.neighbors(s, tenant, estate["web"], FULL_SCOPE, limit=1)
        assert len(limited["neighbors"]) == 1 and limited["truncated"] is True


def test_subgraph_depth_and_truncation(db, tenant, query, estate):
    with db.transaction() as s:
        zero = query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=0)
        assert len(zero["nodes"]) == 1 and zero["edges"] == []
        one = query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=1)
        assert {n["type"] for n in one["nodes"]} == {"Asset", "Software", "Finding"}
        assert len(one["edges"]) == 3
        two = query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=2)
        assert len(two["nodes"]) == 7 and two["truncated"] is False
        assert len(two["edges"]) == 7
        capped = query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=2, max_nodes=3)
        assert len(capped["nodes"]) == 3 and capped["truncated"] is True
        with pytest.raises(ValidationFailed):
            query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=99)
        with pytest.raises(NotFound):
            query.subgraph(s, tenant, ["0" * 32], FULL_SCOPE)


def test_shortest_path_directed_and_undirected(db, tenant, query, estate):
    with db.transaction() as s:
        path = query.shortest_path(s, tenant, estate["sw"], estate["id"], FULL_SCOPE)
        assert path["found"] and path["length"] == 3
        assert [n["id"] for n in path["nodes"]] == [estate["sw"], estate["web"], estate["db"], estate["id"]]
        directed = query.shortest_path(s, tenant, estate["web"], estate["cve"], FULL_SCOPE, directed=True)
        assert directed["length"] == 2
        assert [e["type"] for e in directed["edges"]] == ["HAS_FINDING", "INSTANCE_OF"]
        none = query.shortest_path(s, tenant, estate["cve"], estate["web"], FULL_SCOPE, directed=True,
                                   edge_types=["HAS_FINDING", "INSTANCE_OF"])
        assert none["found"] is False
        same = query.shortest_path(s, tenant, estate["web"], estate["web"], FULL_SCOPE)
        assert same["length"] == 0


def test_shortest_path_matches_reference_bfs_on_random_graphs(db, tenant, query, load):
    rng = random.Random(7)
    n = 40
    nodes = [{"type": "Asset", "identifiers": {"asset_id": f"n{i}"}, "ref": f"n{i}"} for i in range(n)]
    pairs = set()
    while len(pairs) < 70:
        a, b = rng.randrange(n), rng.randrange(n)
        if a != b:
            pairs.add((a, b))
    refs = load(nodes=nodes, edges=[{"type": "CONNECTS_TO", "source": {"ref": f"n{a}"}, "target": {"ref": f"n{b}"}}
                                    for a, b in pairs]).refs
    forward: dict[int, set[int]] = {}
    undirected: dict[int, set[int]] = {}
    for a, b in pairs:
        forward.setdefault(a, set()).add(b)
        undirected.setdefault(a, set()).add(b)
        undirected.setdefault(b, set()).add(a)

    def reference(adjacency, start, goal):
        seen, queue = {start: 0}, deque([start])
        while queue:
            current = queue.popleft()
            if current == goal:
                return seen[current]
            for nxt in adjacency.get(current, ()):
                if nxt not in seen:
                    seen[nxt] = seen[current] + 1
                    queue.append(nxt)
        return None

    with db.transaction() as s:
        for _ in range(60):
            a, b = rng.randrange(n), rng.randrange(n)
            for directed, adjacency in ((True, forward), (False, undirected)):
                expected = reference(adjacency, a, b)
                got = query.shortest_path(s, tenant, refs[f"n{a}"], refs[f"n{b}"], FULL_SCOPE, directed=directed,
                                          max_depth=6)
                if expected is None or expected > 6:
                    assert got["found"] is False, (a, b, directed)
                else:
                    assert got["length"] == expected, (a, b, directed)
                    ids = [node["id"] for node in got["nodes"]]
                    assert ids[0] == refs[f"n{a}"] and ids[-1] == refs[f"n{b}"] and len(ids) == expected + 1
                    for edge, left, right in zip(got["edges"], ids[:-1], ids[1:], strict=True):
                        assert {edge["source"], edge["target"]} == {left, right}
                        if directed:
                            assert (edge["source"], edge["target"]) == (left, right)


def test_pattern_match_internet_exposed_assets_with_open_kev_findings(db, tenant, query, estate):
    pattern = {
        "start": {"type": "Asset", "where": {"internet_exposed": True}},
        "steps": [
            {"edge": "HAS_FINDING", "direction": "out", "node": {"type": "Finding", "where": {"status": "open"}}},
            {"edge": "INSTANCE_OF", "direction": "out", "node": {"type": "Vulnerability", "where": {"kev": True}}},
        ],
    }
    with db.transaction() as s:
        result = query.match(s, tenant, pattern, FULL_SCOPE)
        assert result["count"] == 1 and result["truncated"] is False
        assert [n["id"] for n in result["matches"][0]["nodes"]] == [estate["web"], estate["f"], estate["cve"]]
        # edge predicates and inbound steps
        who = query.match(s, tenant, {
            "start": {"id": estate["db"]},
            "steps": [{"edge": "HAS_ACCESS", "direction": "in", "where": {"privilege": "admin"},
                       "node": {"type": "Identity"}}],
        }, FULL_SCOPE)
        assert [m["nodes"][1]["name"] for m in who["matches"]] == ["Asha Rao"]
        nobody = query.match(s, tenant, {
            "start": {"id": estate["db"]},
            "steps": [{"edge": "HAS_ACCESS", "direction": "in", "where": {"privilege": "read"}}],
        }, FULL_SCOPE)
        assert nobody["count"] == 0
        with pytest.raises(ValidationFailed):
            query.match(s, tenant, {"start": {"type": "Asset"}, "steps": [{"edge": "NOPE"}]}, FULL_SCOPE)
        with pytest.raises(ValidationFailed):
            query.match(s, tenant, {"start": {"type": "Asset"}, "steps": [], "cypher": "MATCH (n)"}, FULL_SCOPE)


def test_personal_data_is_masked_without_pii_permission(db, tenant, query, estate):
    masked = AccessScope(node_types=None, pii=False)
    with db.transaction() as s:
        clear = query.get_node(s, tenant, estate["id"], FULL_SCOPE)
        assert clear["name"] == "Asha Rao" and clear["identifiers"]["upn"] == ["asha.rao@example.com"]
        node = query.get_node(s, tenant, estate["id"], masked)
        assert node["name"].startswith("Identity-") and "Asha" not in str(node)
        assert node["properties"]["display_name"] == "***"
        assert node["properties"]["privileged"] is True  # non-personal attributes stay usable
        assert node["identifiers"]["upn"][0].startswith("masked:")
        assert node["identifiers"]["account"] == ["corp\\arao"]
        # masked callers cannot use search or lookup as an oracle for personal data
        assert query.search(s, tenant, masked, text="asha")["total"] == 0
        assert query.find_by_identifier(s, tenant, masked, value="asha.rao@example.com") == []
        with pytest.raises(PermissionDenied):
            query.search(s, tenant, masked, types=["Identity"], where={"display_name": "Asha Rao"})
        with pytest.raises(PermissionDenied):
            query.find_by_identifier(s, tenant, masked, value="asha.rao@example.com", node_type="Identity", kind="upn")
        history = query.history(s, tenant, estate["id"], masked)
        assert "Asha" not in str(history)


def test_type_restricted_scope_hides_other_types_everywhere(db, tenant, query, estate):
    scope = AccessScope(node_types=frozenset({"Asset", "Finding", "Vulnerability"}), pii=False)
    with db.transaction() as s:
        with pytest.raises(NotFound):
            query.get_node(s, tenant, estate["id"], scope)
        assert {n["type"] for n in query.search(s, tenant, scope)["items"]} == {"Asset", "Finding", "Vulnerability"}
        around = query.neighbors(s, tenant, estate["db"], scope)
        assert {n["node"]["type"] for n in around["neighbors"]} == {"Asset", "Finding"}
        sub = query.subgraph(s, tenant, [estate["web"]], scope, depth=3)
        assert {n["type"] for n in sub["nodes"]} == {"Asset", "Finding", "Vulnerability"}
        # a path that exists only through a hidden node is not revealed
        hidden = query.shortest_path(s, tenant, estate["web"], estate["cve"], scope, edge_types=["RUNS", "AFFECTS"])
        assert hidden["found"] is False
        stats = query.stats(s, tenant, scope)
        assert set(stats["nodes"]) == {"Asset", "Finding", "Vulnerability"} and stats["edges"] == {}


def test_as_of_neighbourhood(db, tenant, query, estate, load):
    before = datetime.now(UTC)
    load(nodes=[{"type": "Asset", "identifiers": {"fqdn": "web-01.dmz.example"}, "ref": "web"},
                {"type": "Asset", "identifiers": {"fqdn": "new.core.example"}, "ref": "new"}],
         edges=[{"type": "CONNECTS_TO", "source": {"ref": "web"}, "target": {"ref": "new"}}])
    with db.transaction() as s:
        now = query.neighbors(s, tenant, estate["web"], FULL_SCOPE, edge_types=["CONNECTS_TO"])
        then = query.neighbors(s, tenant, estate["web"], FULL_SCOPE, edge_types=["CONNECTS_TO"], as_of=before)
        assert len(now["neighbors"]) == 2 and len(then["neighbors"]) == 1
        sub = query.subgraph(s, tenant, [estate["web"]], FULL_SCOPE, depth=1, as_of=before)
        assert "new" not in {n["name"] for n in sub["nodes"]}

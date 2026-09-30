"""Ingestion: idempotency, versioning, quarantine, entity resolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from secgraph.store.models import (
    ChangeEvent,
    Edge,
    IngestBatch,
    Node,
    NodeAlias,
    NodeVersion,
    QuarantinedRecord,
    ResolutionConflict,
)
from secgraph.store.repository import GraphReader


def _asset(**identifiers):
    return {"type": "Asset", "identifiers": identifiers}


def test_create_then_resend_is_idempotent(db, tenant, load):
    batch = {
        "nodes": [
            {
                "type": "Asset",
                "identifiers": {"fqdn": "WEB-01.Corp.Example."},
                "properties": {"criticality": "4"},
                "ref": "a",
            },
            {
                "type": "Vulnerability",
                "identifiers": {"cve": "cve-2021-44228"},
                "properties": {"cvss_score": 10},
                "ref": "v",
            },
            {"type": "Finding", "identifiers": {"finding_key": "scan:1"}, "properties": {"status": "Open"}, "ref": "f"},
        ],
        "edges": [
            {"type": "HAS_FINDING", "source": {"ref": "a"}, "target": {"ref": "f"}},
            {"type": "INSTANCE_OF", "source": {"ref": "f"}, "target": {"ref": "v"}},
        ],
    }
    first = load(**batch)
    assert first.nodes.created == 3 and first.edges.created == 2
    assert not first.rejections
    second = load(**batch)
    assert second.nodes.created == 0 and second.nodes.updated == 0 and second.nodes.unchanged == 3
    assert second.edges.created == 0 and second.edges.unchanged == 2
    assert first.refs == second.refs

    with db.transaction() as s:
        node = s.get(Node, first.refs["a"])
        assert node.name == "web-01"  # hostname derived from the FQDN outranks the FQDN itself
        assert node.properties == {"criticality": 4}  # "4" coerced to the declared integer
        assert node.version == 1
        aliases = {
            (a.kind, a.value) for a in s.execute(select(NodeAlias).where(NodeAlias.node_id == node.id)).scalars()
        }
        assert aliases == {("fqdn", "web-01.corp.example"), ("hostname", "web-01")}
        assert (
            s.execute(select(func.count()).select_from(NodeVersion).where(NodeVersion.tenant_id == tenant)).scalar_one()
            == 0
        )
        events = [
            e.kind
            for e in s.execute(
                select(ChangeEvent).where(ChangeEvent.tenant_id == tenant).order_by(ChangeEvent.seq)
            ).scalars()
        ]
        assert events == ["node.created"] * 3 + ["edge.created"] * 2
        batches = s.execute(select(IngestBatch).where(IngestBatch.tenant_id == tenant)).scalars().all()
        assert [b.status for b in batches] == ["completed", "completed"]
        assert batches[0].ontology_version == "1.0.0"


def test_property_change_creates_a_version_and_history_is_readable(db, tenant, load):
    r1 = load(nodes=[{**_asset(fqdn="db-01.corp.example"), "properties": {"os": "RHEL 8", "criticality": 3}}])
    before = datetime.now(UTC)
    r2 = load(nodes=[{**_asset(fqdn="db-01.corp.example"), "properties": {"os": "RHEL 9"}}])
    assert r2.nodes.updated == 1
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        (node_id,) = reader.find_by_identifier("db-01.corp.example")
        now = reader.get_node(node_id)
        assert now.version == 2 and now.properties == {"os": "RHEL 9", "criticality": 3}
        then = reader.get_node(node_id, as_of=before)
        assert then.version == 1 and then.properties == {"os": "RHEL 8", "criticality": 3}
        assert reader.get_node(node_id, as_of=before - timedelta(days=1)) is None  # did not exist yet
        history = reader.node_history(node_id)
        assert [h["version"] for h in history] == [2, 1]
        assert history[1]["valid_to"] == history[0]["valid_from"]
    assert r1.batch_id != r2.batch_id


def test_null_removes_a_property(db, tenant, load):
    load(nodes=[{**_asset(fqdn="a.corp.example"), "properties": {"os": "Windows", "owner": "ops"}}])
    load(nodes=[{**_asset(fqdn="a.corp.example"), "properties": {"owner": None}}])
    with db.transaction() as s:
        node = s.execute(select(Node).where(Node.tenant_id == tenant)).scalar_one()
        assert node.properties == {"os": "Windows"}
        assert node.prop_sources == {"os": "test"}


def test_invalid_records_are_quarantined_not_dropped(db, tenant, load):
    result = load(
        nodes=[
            _asset(fqdn="good.corp.example"),
            {"type": "Asset", "identifiers": {"mac": "not-a-mac"}},
            {"type": "Asset", "identifiers": {"fqdn": "x.corp.example"}, "properties": {"criticality": 9}},
            {"type": "Nonsense", "identifiers": {"x": "y"}},
            {"type": "Control", "identifiers": {"control_key": "c1"}},  # control_type is required
            {"type": "Asset", "identifiers": {"ip": "10.0.0.1"}},  # ip alone cannot identify an entity
            "not even an object",
            {"type": "Asset", "identifiers": {"fqdn": "y.corp.example"}, "surprise": 1},
        ],
        edges=[
            {"type": "HAS_FINDING", "source": {"ref": "nope"}, "target": {"ref": "nope2"}},
            {
                "type": "HAS_FINDING",
                "source": {"type": "Asset", "identifiers": {"fqdn": "good.corp.example"}},
                "target": {"type": "Asset", "identifiers": {"fqdn": "other.corp.example"}},
            },
        ],
    )
    assert result.nodes.created == 1
    assert result.nodes.quarantined == 7
    assert result.edges.quarantined == 2
    reasons = " | ".join(r.reason for r in result.rejections)
    assert "not a MAC address" in reasons
    assert "above the maximum 5" in reasons
    assert "unknown node type 'Nonsense'" in reasons
    assert "Control.control_type: required" in reasons
    assert "can identify an entity" in reasons
    assert "unknown ref 'nope'" in reasons
    assert "target must be one of Finding" in reasons
    with db.transaction() as s:
        rows = s.execute(select(QuarantinedRecord).where(QuarantinedRecord.tenant_id == tenant)).scalars().all()
        assert len(rows) == 9
        assert all(r.status == "open" and r.batch_id == result.batch_id for r in rows)


def test_edge_endpoint_by_identifier_creates_stub_then_full_record_fills_it(db, tenant, load):
    r = load(
        nodes=[{**_asset(fqdn="h.corp.example"), "ref": "h"}],
        edges=[
            {
                "type": "RUNS",
                "source": {"ref": "h"},
                "target": {"type": "Software", "identifiers": {"purl": "pkg:maven/org.apache/log4j-core@2.14.1"}},
            }
        ],
    )
    assert r.stubs_created == 1 and r.edges.created == 1
    with db.transaction() as s:
        sw = s.execute(select(Node).where(Node.tenant_id == tenant, Node.type == "Software")).scalar_one()
        assert sw.stub is True and sw.version == 1
    r2 = load(
        nodes=[
            {
                "type": "Software",
                "identifiers": {"purl": "pkg:maven/org.apache/log4j-core@2.14.1"},
                "properties": {"name": "log4j-core", "version": "2.14.1"},
            }
        ]
    )
    assert r2.nodes.updated == 1 and r2.nodes.created == 0
    with db.transaction() as s:
        sw = s.execute(select(Node).where(Node.tenant_id == tenant, Node.type == "Software")).scalar_one()
        assert sw.stub is False and sw.version == 2 and sw.name == "log4j-core"


def test_edge_versions_and_delete(db, tenant, load):
    nodes = [{**_asset(fqdn="a.corp.example"), "ref": "a"}, {**_asset(fqdn="b.corp.example"), "ref": "b"}]
    edge = {
        "type": "CONNECTS_TO",
        "source": {"ref": "a"},
        "target": {"ref": "b"},
        "key": "tcp/443",
        "properties": {"port": 443, "protocol": "tcp"},
    }
    load(nodes=nodes, edges=[edge])
    t1 = datetime.now(UTC)
    r = load(nodes=nodes, edges=[{**edge, "properties": {"port": 443, "protocol": "tcp", "service": "https"}}])
    assert r.edges.updated == 1
    t2 = datetime.now(UTC)
    r = load(nodes=nodes, edges=[{**edge, "op": "delete"}])
    assert r.edges.deleted == 1
    r = load(nodes=nodes, edges=[{**edge, "op": "delete"}])
    assert r.edges.unchanged == 1
    with db.transaction() as s:
        rows = s.execute(select(Edge).where(Edge.tenant_id == tenant).order_by(Edge.version)).scalars().all()
        assert [(e.version, e.valid_to is None) for e in rows] == [(1, False), (2, False)]
        assert rows[0].lineage_id == rows[1].lineage_id
        reader = GraphReader(s, tenant)
        a = reader.find_by_identifier("a.corp.example")[0]
        assert reader.edges_of([a])[0] == []
        at_t1, _ = reader.edges_of([a], as_of=t1)
        assert [e.properties for e in at_t1] == [{"port": 443, "protocol": "tcp"}]
        at_t2, _ = reader.edges_of([a], as_of=t2)
        assert at_t2[0].properties["service"] == "https" and at_t2[0].version == 2


def test_node_delete_closes_edges_and_reingest_restores_same_id(db, tenant, load):
    nodes = [{**_asset(fqdn="a.corp.example"), "ref": "a"}, {**_asset(fqdn="b.corp.example"), "ref": "b"}]
    r = load(nodes=nodes, edges=[{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "b"}}])
    a_id = r.refs["a"]
    before_delete = datetime.now(UTC)
    d = load(nodes=[{**_asset(fqdn="a.corp.example"), "op": "delete"}])
    assert d.nodes.deleted == 1
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        assert reader.get_node(a_id) is None
        assert reader.get_node(a_id, include_deleted=True).deleted is True
        assert reader.get_node(a_id, as_of=before_delete) is not None
        assert reader.edges_of([r.refs["b"]])[0] == []
        assert len(reader.edges_of([r.refs["b"]], as_of=before_delete)[0]) == 1
    back = load(nodes=[{**_asset(fqdn="a.corp.example"), "ref": "a"}])
    assert back.refs["a"] == a_id and back.nodes.updated == 1
    with db.transaction() as s:
        assert GraphReader(s, tenant).get_node(a_id).version == 3


def test_self_loops_are_rejected(tenant, load):
    r = load(
        nodes=[{**_asset(fqdn="a.corp.example"), "ref": "a"}],
        edges=[{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "a"}}],
    )
    assert r.edges.quarantined == 1 and "same entity" in r.rejections[0].reason


# ---- entity resolution ------------------------------------------------------
def _assets(db, tenant):
    with db.transaction() as s:
        return (
            s.execute(select(Node).where(Node.tenant_id == tenant, Node.type == "Asset", Node.deleted_at.is_(None)))
            .scalars()
            .all()
        )


def test_two_sources_describing_one_host_merge_on_a_strong_identifier(db, tenant, load):
    load(
        nodes=[{**_asset(fqdn="web-01.corp.example", mac="00-1A-2B-3C-4D-5E"), "properties": {"os": "Ubuntu"}}],
        source="cmdb",
    )
    load(nodes=[{**_asset(mac="001a.2b3c.4d5e", agent_id="EDR-77"), "properties": {"owner": "payments"}}], source="edr")
    assets = _assets(db, tenant)
    assert len(assets) == 1
    assert assets[0].properties == {"os": "Ubuntu", "owner": "payments"}
    assert assets[0].sources.keys() == {"cmdb", "edr"}


def test_weak_hostname_merges_only_when_unambiguous_and_compatible(db, tenant, load):
    load(nodes=[_asset(fqdn="web-01.prod.example")], source="cmdb")
    # EDR knows only the short name: exactly one compatible candidate, so it is the same host.
    load(nodes=[_asset(hostname="WEB-01", agent_id="edr-1")], source="edr")
    assert len(_assets(db, tenant)) == 1
    # A different FQDN with the same short name is a different host (fqdn is exclusive).
    load(nodes=[_asset(fqdn="web-01.dev.example")], source="cmdb")
    assert len(_assets(db, tenant)) == 2
    # A second EDR agent with the same short name: prod is taken (agent_id differs), dev is free.
    load(nodes=[_asset(hostname="web-01", agent_id="edr-2")], source="edr")
    assets = _assets(db, tenant)
    assert len(assets) == 2
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        ids = reader.identifiers_for([a.id for a in assets])
    by_fqdn = {v["fqdn"][0]: v for v in ids.values()}
    assert by_fqdn["web-01.prod.example"]["agent_id"] == ["edr-1"]
    assert by_fqdn["web-01.dev.example"]["agent_id"] == ["edr-2"]


def test_ambiguous_weak_match_creates_a_new_node_and_a_conflict(db, tenant, load):
    load(nodes=[_asset(fqdn="app.prod.example"), _asset(fqdn="app.dev.example")])
    r = load(nodes=[_asset(hostname="app")])
    assert r.nodes.created == 1 and r.conflicts == 1
    assert len(_assets(db, tenant)) == 3
    with db.transaction() as s:
        conflict = s.execute(select(ResolutionConflict).where(ResolutionConflict.tenant_id == tenant)).scalar_one()
        assert conflict.reason == "ambiguous_weak_match" and len(conflict.node_ids) == 2
    # The same ambiguity again is counted, not duplicated — and the record now matches its own node.
    r = load(nodes=[_asset(hostname="app")])
    assert r.nodes.created == 0
    assert len(_assets(db, tenant)) == 3


def test_strong_match_contradicted_by_exclusive_identifier_is_not_merged(db, tenant, load):
    load(nodes=[_asset(serial="SN-1", mac="aa:bb:cc:00:00:01")])
    # Same MAC (cloned VM / re-used NIC) but a different serial number: a different machine.
    r = load(nodes=[_asset(serial="SN-2", mac="aa:bb:cc:00:00:01")])
    assert r.nodes.created == 1 and r.conflicts == 1
    assert len(_assets(db, tenant)) == 2
    with db.transaction() as s:
        conflict = s.execute(select(ResolutionConflict).where(ResolutionConflict.tenant_id == tenant)).scalar_one()
        assert conflict.reason == "exclusive_mismatch"
    r = load(nodes=[_asset(serial="SN-2", mac="aa:bb:cc:00:00:01")])
    assert r.nodes.created == 0 and r.nodes.unchanged == 1 and len(_assets(db, tenant)) == 2


def test_record_matching_two_entities_prefers_the_stronger_identifier(db, tenant, load):
    a = load(nodes=[{**_asset(serial="SN-A"), "ref": "a"}]).refs["a"]
    load(nodes=[{**_asset(mac="aa:bb:cc:00:00:02"), "ref": "b"}])
    r = load(nodes=[{**_asset(serial="SN-A", mac="aa:bb:cc:00:00:02"), "ref": "x"}])
    assert r.refs["x"] == a  # serial outranks mac in the ontology
    assert r.conflicts == 1
    with db.transaction() as s:
        conflict = s.execute(select(ResolutionConflict).where(ResolutionConflict.tenant_id == tenant)).scalar_one()
        assert conflict.reason == "multiple_strong_matches" and len(conflict.node_ids) == 2


def test_ip_is_searchable_but_never_merges(db, tenant, load):
    load(nodes=[_asset(fqdn="one.corp.example", ip="10.0.0.9")])
    load(nodes=[_asset(fqdn="two.corp.example", ip="10.0.0.9")])
    assert len(_assets(db, tenant)) == 2
    with db.transaction() as s:
        assert len(GraphReader(s, tenant).find_by_identifier("10.0.0.9")) == 2


def test_duplicates_inside_one_batch_resolve_to_one_node(db, tenant, load):
    r = load(
        nodes=[
            {**_asset(fqdn="dup.corp.example"), "properties": {"os": "A"}, "ref": "1"},
            {**_asset(fqdn="DUP.corp.example"), "properties": {"owner": "x"}, "ref": "2"},
        ]
    )
    assert r.refs["1"] == r.refs["2"]
    assert r.nodes.created == 1 and r.nodes.updated == 1
    assert _assets(db, tenant)[0].properties == {"os": "A", "owner": "x"}


# ---- source priority and staleness -----------------------------------------
def test_lower_priority_source_cannot_overwrite_higher(db, ontology, tenant):
    from secgraph.ingest.canonical import IngestRequest
    from secgraph.ingest.service import IngestService
    from tests.conftest import make_settings

    service = IngestService(db, ontology, make_settings(db.settings.database_url, source_priority="cmdb,scanner"))

    def send(source, props):
        return service.ingest(
            tenant,
            "user:test",
            IngestRequest(source=source, nodes=[{**_asset(fqdn="p.corp.example"), "properties": props}]),
        )

    send("cmdb", {"owner": "payments", "os": "RHEL"})
    r = send("scanner", {"owner": "unknown", "location": "DC1"})
    assert r.nodes.updated == 1  # location is new
    send("discovery", {"os": "Linux"})  # unlisted sources rank below listed ones
    node = _assets(db, tenant)[0]
    assert node.properties == {"owner": "payments", "os": "RHEL", "location": "DC1"}
    send("cmdb", {"location": "DC2"})  # the higher-priority source may overwrite
    assert _assets(db, tenant)[0].properties["location"] == "DC2"


def test_older_observation_from_same_source_does_not_overwrite(db, tenant, load):
    now = datetime.now(UTC)
    load(nodes=[{**_asset(fqdn="s.corp.example"), "properties": {"os": "new"}}], observed_at=now.isoformat())
    r = load(
        nodes=[{**_asset(fqdn="s.corp.example"), "properties": {"os": "old", "owner": "late"}}],
        observed_at=(now - timedelta(days=2)).isoformat(),
    )
    assert r.nodes.updated == 1  # owner was missing, so it is filled
    node = _assets(db, tenant)[0]
    assert node.properties == {"os": "new", "owner": "late"}
    assert node.first_seen < node.last_seen


def test_future_timestamp_is_rejected(tenant, load):
    future = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    r = load(nodes=[{**_asset(fqdn="f.corp.example"), "observed_at": future}])
    assert r.nodes.quarantined == 1 and "future" in r.rejections[0].reason


def test_tenants_are_isolated(db, ingest_service, load, tenant):
    from secgraph.ingest.canonical import IngestRequest

    load(nodes=[_asset(fqdn="shared.corp.example")])
    other = tenant + "-b"
    r = ingest_service.ingest(
        other, "user:test", IngestRequest(source="test", nodes=[_asset(fqdn="shared.corp.example")])
    )
    assert r.nodes.created == 1  # same identifier, different tenant: a different node
    with db.transaction() as s:
        assert len(GraphReader(s, tenant).find_by_identifier("shared.corp.example")) == 1
        assert GraphReader(s, other).count_nodes_by_type() == {"Asset": 1}


def test_batch_size_limit(db, ontology, tenant):
    import pytest

    from secgraph.errors import LimitExceeded
    from secgraph.ingest.canonical import IngestRequest
    from secgraph.ingest.service import IngestService
    from tests.conftest import make_settings

    service = IngestService(db, ontology, make_settings(db.settings.database_url, ingest_max_records=2))
    with pytest.raises(LimitExceeded):
        service.ingest(
            tenant, "u", IngestRequest(source="t", nodes=[_asset(fqdn=f"h{i}.corp.example") for i in range(3)])
        )


def test_chunking_keeps_refs_across_chunks(db, ontology, tenant):
    from secgraph.ingest.canonical import IngestRequest
    from secgraph.ingest.service import IngestService
    from tests.conftest import make_settings

    service = IngestService(db, ontology, make_settings(db.settings.database_url, ingest_chunk_size=3))
    nodes = [{**_asset(fqdn=f"n{i}.corp.example"), "ref": f"n{i}"} for i in range(10)]
    edges = [{"type": "CONNECTS_TO", "source": {"ref": f"n{i}"}, "target": {"ref": f"n{i + 1}"}} for i in range(9)]
    r = service.ingest(tenant, "u", IngestRequest(source="t", nodes=nodes, edges=edges))
    assert r.nodes.created == 10 and r.edges.created == 9
    with db.transaction() as s:
        seqs = [
            e.seq
            for e in s.execute(
                select(ChangeEvent).where(ChangeEvent.tenant_id == tenant).order_by(ChangeEvent.seq)
            ).scalars()
        ]
        assert seqs == list(range(1, 20))


# ---- curation ---------------------------------------------------------------
def _curation(db, ontology, settings, ingest_service):
    from secgraph.ingest.curation import CurationService

    return CurationService(db, ontology, settings, ingest_service)


def test_merge_moves_identity_edges_and_redirects_old_id(db, ontology, settings, ingest_service, tenant, load):
    r = load(
        nodes=[
            {**_asset(fqdn="app.prod.example"), "properties": {"os": "RHEL"}, "ref": "keep"},
            {
                **_asset(agent_id="edr-9", hostname="app2"),
                "properties": {"os": "Linux", "owner": "payments"},
                "ref": "dup",
            },
            {**_asset(fqdn="peer.corp.example"), "ref": "peer"},
            {"type": "Finding", "identifiers": {"finding_key": "f1"}, "ref": "f"},
        ],
        edges=[
            {"type": "HAS_FINDING", "source": {"ref": "dup"}, "target": {"ref": "f"}},
            {"type": "CONNECTS_TO", "source": {"ref": "dup"}, "target": {"ref": "peer"}},
            {"type": "CONNECTS_TO", "source": {"ref": "keep"}, "target": {"ref": "peer"}},
            {"type": "CONNECTS_TO", "source": {"ref": "dup"}, "target": {"ref": "keep"}},
        ],
    )
    keep, dup = r.refs["keep"], r.refs["dup"]
    before = datetime.now(UTC)
    summary = _curation(db, ontology, settings, ingest_service).merge_nodes(tenant, "user:steward", keep, dup)
    assert summary["aliases_moved"] == 2 and summary["edges_moved"] == 1
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        assert reader.resolve_id(dup) == keep
        node = reader.get_node(keep)
        assert node.properties == {"os": "RHEL", "owner": "payments"}  # survivor wins, gaps filled
        assert reader.get_node(dup) is None
        edges, _ = reader.edges_of([keep])
        assert sorted((e.type, e.target) for e in edges) == sorted(
            [("HAS_FINDING", r.refs["f"]), ("CONNECTS_TO", r.refs["peer"])]
        )
        ids = reader.identifiers_for([keep])[keep]
        assert ids["agent_id"] == ["edr-9"] and ids["fqdn"] == ["app.prod.example"]
        # history is intact: before the merge the duplicate existed with its own edges
        assert reader.get_node(dup, as_of=before) is not None
        assert len(reader.edges_of([dup], as_of=before)[0]) == 3
    # a record carrying the duplicate's identifier now lands on the survivor
    again = load(nodes=[{**_asset(agent_id="edr-9"), "ref": "x"}])
    assert again.refs["x"] == keep


def test_merge_refuses_different_types_and_missing_nodes(db, ontology, settings, ingest_service, tenant, load):
    import pytest

    from secgraph.errors import Conflict, NotFound, ValidationFailed

    r = load(
        nodes=[
            {**_asset(fqdn="a.corp.example"), "ref": "a"},
            {"type": "Finding", "identifiers": {"finding_key": "f"}, "ref": "f"},
        ]
    )
    curation = _curation(db, ontology, settings, ingest_service)
    with pytest.raises(Conflict):
        curation.merge_nodes(tenant, "u", r.refs["a"], r.refs["f"])
    with pytest.raises(NotFound):
        curation.merge_nodes(tenant, "u", r.refs["a"], "0" * 32)
    with pytest.raises(ValidationFailed):
        curation.merge_nodes(tenant, "u", r.refs["a"], r.refs["a"])


def test_quarantine_replay_after_fix(db, ontology, settings, ingest_service, tenant, load):
    r = load(nodes=[{"type": "Control", "identifiers": {"control_key": "waf-1"}, "properties": {"name": "Edge WAF"}}])
    assert r.nodes.quarantined == 1
    curation = _curation(db, ontology, settings, ingest_service)
    rows, total = curation.list_quarantine(tenant)
    assert total == 1 and "control_type: required" in rows[0].reason
    # The steward fixes the stored record, then replays it.
    with db.transaction() as s:
        row = s.get(QuarantinedRecord, rows[0].id)
        row.record = {**row.record, "properties": {**row.record["properties"], "control_type": "waf"}}
    out = curation.replay_quarantine(tenant, "user:steward", [rows[0].id])
    assert out["replayed"] == 1 and out["batches"][0]["nodes"]["created"] == 1
    assert curation.list_quarantine(tenant)[1] == 0
    assert curation.list_quarantine(tenant, status="replayed")[1] == 1


def test_ttl_expiry_closes_stale_edges_and_nodes(db, ontology, settings, ingest_service, tenant, load):
    old = (datetime.now(UTC) - timedelta(days=45)).isoformat()
    nodes = [
        {**_asset(fqdn="a.corp.example"), "ref": "a"},
        {**_asset(fqdn="b.corp.example"), "ref": "b"},
        {**_asset(fqdn="c.corp.example"), "ref": "c"},
    ]
    load(nodes=nodes, edges=[{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "b"}}], observed_at=old)
    load(nodes=nodes, edges=[{"type": "CONNECTS_TO", "source": {"ref": "a"}, "target": {"ref": "c"}}])
    load(
        nodes=[{"type": "Indicator", "identifiers": {"indicator": "198.51.100.7"}}],
        observed_at=(datetime.now(UTC) - timedelta(days=400)).isoformat(),
    )
    curation = _curation(db, ontology, settings, ingest_service)
    assert curation.expire_stale(tenant) == {"nodes": 1, "edges": 1}  # CONNECTS_TO ttl 30d, Indicator ttl 180d
    assert curation.expire_stale(tenant) == {"nodes": 0, "edges": 0}
    with db.transaction() as s:
        reader = GraphReader(s, tenant)
        assert reader.count_edges_by_type() == {"CONNECTS_TO": 1}
        assert "Indicator" not in reader.count_nodes_by_type()
        assert reader.count_nodes_by_type()["Asset"] == 3  # assets have no TTL


def test_planner_statistics_are_refreshed_as_a_tenant_grows(ingest_service, monkeypatch):
    """A first load must not outrun the statistics the database plans with; a reload must not pay for them."""
    import uuid

    refreshed: list[str] = []
    monkeypatch.setattr(ingest_service.db, "refresh_statistics", lambda: refreshed.append("x") or True)
    tenant = "growth-" + uuid.uuid4().hex[:8]

    ingest_service._note_growth(tenant, 0)  # nothing new: never refresh
    ingest_service._note_growth(tenant, 4_999)
    assert refreshed == []
    ingest_service._note_growth(tenant, 1)  # 5,000 new rows
    assert len(refreshed) == 1

    for _ in range(200):  # a further 100,000 rows in chunks of 500
        ingest_service._note_growth(tenant, 500)
    assert 8 <= len(refreshed) <= 16  # the interval widens as the tenant grows: not once per chunk

    before = len(refreshed)
    ingest_service._note_growth("another-" + tenant, 100)  # tenants are tracked separately
    assert len(refreshed) == before


def test_refresh_statistics_runs_on_postgresql_and_is_a_no_op_elsewhere(db):
    assert db.refresh_statistics() is (db.dialect == "postgresql")
    assert db.refresh_statistics(("not_a_table",)) is False  # refused, never interpolated into SQL

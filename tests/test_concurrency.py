"""Concurrent writers. These matter most on PostgreSQL, where transactions really do interleave."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import func, select

from secgraph.governance import audit
from secgraph.ingest.canonical import IngestRequest
from secgraph.store.models import AuditEntry, ChangeEvent, Edge, Node, NodeAlias


def test_parallel_batches_describing_the_same_entities_create_each_once(db, ingest_service, tenant):
    """Eight writers race to create the same 40 hosts and 39 links. Exactly one node and one edge each survive."""
    nodes = [{"type": "Asset", "identifiers": {"fqdn": f"race-{i}.corp.example", "mac": f"02:00:00:00:{i:02x}:01"},
              "properties": {"criticality": 3}, "ref": f"n{i}"} for i in range(40)]
    edges = [{"type": "CONNECTS_TO", "source": {"ref": f"n{i}"}, "target": {"ref": f"n{i + 1}"}} for i in range(39)]

    def writer(index: int):
        request = IngestRequest(source=f"writer-{index}", nodes=nodes, edges=edges)
        return ingest_service.ingest(tenant, f"svc:{index}", request)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(writer, range(8)))
    assert all(not r.rejections for r in results)
    assert sum(r.nodes.created for r in results) == 40
    assert sum(r.edges.created for r in results) == 39
    with db.transaction() as s:
        assert s.execute(select(func.count()).select_from(Node).where(Node.tenant_id == tenant)).scalar_one() == 40
        current = s.execute(select(func.count()).select_from(Edge).where(
            Edge.tenant_id == tenant, Edge.valid_to.is_(None))).scalar_one()
        assert current == 39
        strong = s.execute(select(NodeAlias.kind, NodeAlias.value, func.count()).where(
            NodeAlias.tenant_id == tenant, NodeAlias.weak.is_(False)).group_by(NodeAlias.kind, NodeAlias.value)).all()
        assert all(count == 1 for _kind, _value, count in strong) and len(strong) == 80
        sources = s.execute(select(Node.sources).where(Node.tenant_id == tenant)).scalars().all()
        assert all(len(sources_of_node) == 8 for sources_of_node in sources)  # every writer's observation is recorded
        # the change feed is gapless and strictly ordered despite the interleaving
        seqs = list(s.execute(select(ChangeEvent.seq).where(ChangeEvent.tenant_id == tenant)
                              .order_by(ChangeEvent.seq)).scalars())
        assert seqs == list(range(1, len(seqs) + 1)) and len(seqs) == 79
        assert audit.verify(s, tenant)["ok"] is True


def test_concurrent_updates_to_one_node_lose_nothing(db, ingest_service, tenant):
    ingest_service.ingest(tenant, "u", IngestRequest(source="seed", nodes=[
        {"type": "Asset", "identifiers": {"fqdn": "hot.corp.example"}}]))

    def writer(index: int):
        return ingest_service.ingest(tenant, "u", IngestRequest(source=f"s{index}", nodes=[
            {"type": "Asset", "identifiers": {"fqdn": "hot.corp.example"}, "properties": {f"attr_{index}": index}}]))

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(writer, range(12)))
    assert sum(r.nodes.updated for r in results) == 12
    with db.transaction() as s:
        node = s.execute(select(Node).where(Node.tenant_id == tenant)).scalar_one()
        assert node.properties == {f"attr_{i}": i for i in range(12)}
        assert node.version == 13


def test_audit_chain_survives_concurrent_appends(db, tenant):
    from secgraph.store.db import ensure_tenant

    db.run(lambda s: ensure_tenant(s, tenant))

    def append(index: int):
        db.run(lambda s: audit.record(s, tenant, actor=f"user:{index}", action="test.event", target=str(index)))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(60)))
    with db.transaction() as s:
        verdict = audit.verify(s, tenant)
        assert verdict["ok"] is True and verdict["entries"] == 60
        seqs = list(s.execute(select(AuditEntry.seq).where(AuditEntry.tenant_id == tenant)
                              .order_by(AuditEntry.seq)).scalars())
        assert seqs == list(range(1, 61))

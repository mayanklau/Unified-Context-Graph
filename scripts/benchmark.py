#!/usr/bin/env python3
"""Measure ingestion, queries and attack-path analytics on a synthetic estate.

    python scripts/benchmark.py                       # 5,000 assets on a temporary SQLite file
    python scripts/benchmark.py --assets 20000
    python scripts/benchmark.py --database-url postgresql+psycopg://secgraph:...@host/secgraph_bench

The estate is generated from a fixed seed, so two runs load the same graph. With
``--database-url`` the schema is created in, and the benchmark tenant written to, that
database: point it at a scratch database, not a live one.

The numbers depend on the machine and the database. Use them to size a deployment, not as
a guarantee.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ZONES = ["dmz", "internal", "internal", "internal", "restricted", "management"]
SEVERITIES = ["critical", "high", "high", "medium", "medium", "medium", "low"]
CONTROL_TYPES = ["waf", "network_ips", "segmentation", "edr", "siem_detection", "mfa", "pam", "patch_management"]


def build_estate(assets: int, seed: int) -> dict[str, list[dict[str, Any]]]:
    """A bank-shaped estate: zones, routed segments, hosts, findings, identities, controls."""
    rng = random.Random(seed)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def asset_ref(i: int) -> dict[str, Any]:
        return {"type": "Asset", "identifiers": {"asset_id": f"BENCH-{i:07d}"}}

    def segment_ref(i: int) -> dict[str, Any]:
        return {"type": "NetworkSegment", "identifiers": {"segment_key": f"seg-{i:04d}"}}

    segment_count = max(6, assets // 250)
    zones = [ZONES[i % len(ZONES)] for i in range(segment_count)]
    for i, zone in enumerate(zones):
        nodes.append(
            {"type": "NetworkSegment", "identifiers": {"segment_key": f"seg-{i:04d}"}, "properties": {"zone": zone}}
        )
    by_zone: dict[str, list[int]] = {}
    for i, zone in enumerate(zones):
        by_zone.setdefault(zone, []).append(i)
    allowed = {"dmz": ["internal"], "internal": ["internal", "restricted"], "management": ["internal", "restricted"]}
    for i, zone in enumerate(zones):
        for target_zone in allowed.get(zone, []):
            for j in rng.sample(by_zone[target_zone], k=min(2, len(by_zone[target_zone]))):
                if i != j:
                    edges.append({"type": "ROUTES_TO", "source": segment_ref(i), "target": segment_ref(j)})

    vulnerability_count = max(50, min(5000, assets // 5))
    for v in range(vulnerability_count):
        kev = rng.random() < 0.04
        nodes.append(
            {
                "type": "Vulnerability",
                "identifiers": {"cve": f"CVE-2025-{10000 + v}"},
                "properties": {
                    "cvss_score": round(rng.uniform(4.0, 9.9), 1),
                    "attack_vector": rng.choice(["network", "network", "adjacent", "local"]),
                    "epss": round(rng.betavariate(0.6, 8.0), 4),
                    "kev": kev,
                },
            }
        )

    finding_number = 0
    for a in range(assets):
        segment = a % segment_count
        zone = zones[segment]
        crown = zone == "restricted" and rng.random() < 0.06
        nodes.append(
            {
                "type": "Asset",
                "identifiers": {
                    "asset_id": f"BENCH-{a:07d}",
                    "fqdn": f"host-{a:07d}.{zone}.bench.example",
                    "ip": f"10.{(a >> 16) & 255}.{(a >> 8) & 255}.{a & 255}",
                },
                "properties": {
                    "asset_type": "server" if zone != "internal" or a % 3 == 0 else "workstation",
                    "environment": "production",
                    "criticality": 5 if crown else rng.randint(1, 4),
                    "crown_jewel": crown,
                    "internet_exposed": zone == "dmz" and rng.random() < 0.5,
                },
            }
        )
        edges.append({"type": "IN_SEGMENT", "source": asset_ref(a), "target": segment_ref(segment)})
        for _ in range(rng.choice([0, 1, 1, 2, 3, 5])):
            finding_number += 1
            key = f"bench:{finding_number}"
            nodes.append(
                {
                    "type": "Finding",
                    "identifiers": {"finding_key": key},
                    "properties": {"status": "open", "severity": rng.choice(SEVERITIES), "scanner": "bench"},
                }
            )
            finding = {"type": "Finding", "identifiers": {"finding_key": key}}
            cve = f"CVE-2025-{10000 + rng.randrange(vulnerability_count)}"
            edges.append({"type": "HAS_FINDING", "source": asset_ref(a), "target": finding})
            edges.append(
                {
                    "type": "INSTANCE_OF",
                    "source": finding,
                    "target": {"type": "Vulnerability", "identifiers": {"cve": cve}},
                }
            )
        for _ in range(rng.choice([0, 1, 2, 3])):
            other = rng.randrange(assets)
            if other != a:
                edges.append(
                    {
                        "type": "CONNECTS_TO",
                        "source": asset_ref(a),
                        "target": asset_ref(other),
                        "key": f"tcp/{rng.choice([22, 443, 1521, 3389, 5432, 8443])}",
                    }
                )

    for i in range(max(10, assets // 5)):
        privileged = rng.random() < 0.05
        identity = {"type": "Identity", "identifiers": {"account": f"bench\\user{i:06d}"}}
        nodes.append({**identity, "properties": {"identity_type": "human", "privileged": privileged}})
        for _ in range(2):
            edges.append(
                {
                    "type": "HAS_ACCESS",
                    "source": identity,
                    "target": asset_ref(rng.randrange(assets)),
                    "properties": {"privilege": rng.choice(["read", "write", "admin"])},
                }
            )
        edges.append({"type": "HAS_SESSION", "source": asset_ref(rng.randrange(assets)), "target": identity})

    for i in range(max(8, segment_count)):
        control_type = CONTROL_TYPES[i % len(CONTROL_TYPES)]
        control = {"type": "Control", "identifiers": {"control_key": f"bench-{control_type}-{i}"}}
        nodes.append(
            {**control, "properties": {"control_type": control_type, "effectiveness": round(rng.uniform(0.4, 0.9), 2)}}
        )
        edges.append({"type": "PROTECTS", "source": control, "target": segment_ref(i % segment_count)})
    return {"nodes": nodes, "edges": edges}


def timed(work: Any, repeat: int = 1) -> tuple[Any, float, list[float]]:
    result, samples = None, []
    for _ in range(repeat):
        started = time.perf_counter()
        result = work()
        samples.append(time.perf_counter() - started)
    return result, statistics.median(samples), samples


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--assets", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--database-url", help="default: a temporary SQLite file")
    parser.add_argument("--batch", type=int, default=20_000, help="records per ingest request")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args()

    from secgraph.config import Settings
    from secgraph.context import build_context
    from secgraph.governance.rbac import Principal
    from secgraph.ingest.canonical import IngestRequest
    from secgraph.store.db import Database

    scratch = tempfile.TemporaryDirectory()
    url = args.database_url or f"sqlite:///{Path(scratch.name) / 'bench.db'}"
    settings = Settings(_env_file=None, database_url=url, log_level="ERROR", log_json=False)  # type: ignore[call-arg]
    db = Database(settings)
    db.create_all()
    ctx = build_context(settings, db=db)
    tenant = "bench-" + uuid.uuid4().hex[:8]
    principal = Principal.build(id="system:bench", name="bench", kind="service", tenant_id=tenant, roles=["admin"])
    out: dict[str, Any] = {
        "machine": {"python": platform.python_version(), "platform": platform.platform(), "database": db.dialect},
    }

    started = time.perf_counter()
    estate = build_estate(args.assets, args.seed)
    out["estate"] = {
        "nodes": len(estate["nodes"]),
        "edges": len(estate["edges"]),
        "generated_s": round(time.perf_counter() - started, 2),
    }

    def ingest() -> dict[str, int]:
        totals = {"nodes": 0, "edges": 0, "quarantined": 0}
        records = [("nodes", n) for n in estate["nodes"]] + [("edges", e) for e in estate["edges"]]
        for offset in range(0, len(records), args.batch):
            chunk = records[offset : offset + args.batch]
            request = IngestRequest(
                source="bench",
                nodes=[r for kind, r in chunk if kind == "nodes"],
                edges=[r for kind, r in chunk if kind == "edges"],
            )
            result = ctx.ingest.ingest(tenant, principal.id, request)
            totals["nodes"] += result.nodes.created + result.nodes.updated + result.nodes.unchanged
            totals["edges"] += result.edges.created + result.edges.updated + result.edges.unchanged
            totals["quarantined"] += result.nodes.quarantined + result.edges.quarantined
        return totals

    records = len(estate["nodes"]) + len(estate["edges"])
    first, first_s, _ = timed(ingest)
    out["ingest_first_load"] = {**first, "seconds": round(first_s, 2), "records_per_s": round(records / first_s)}
    _, again_s, _ = timed(ingest)
    out["ingest_unchanged_reload"] = {"seconds": round(again_s, 2), "records_per_s": round(records / again_s)}

    scope = principal.scope

    def read(work: Any) -> Any:
        with db.snapshot() as session:
            return work(session)

    sample = read(lambda s: ctx.query.search(s, tenant, scope, types=["Asset"], limit=50))["items"]
    ids = [item["id"] for item in sample]
    _, lookup_s, _ = timed(
        lambda: read(lambda s: ctx.query.find_by_identifier(s, tenant, scope, value="host-0000042.dmz.bench.example")),
        20,
    )
    _, neighbours_s, _ = timed(
        lambda: [read(lambda s, i=i: ctx.query.neighbors(s, tenant, i, scope)) for i in ids[:20]], 5
    )
    _, subgraph_s, _ = timed(
        lambda: read(lambda s: ctx.query.subgraph(s, tenant, ids[:1], scope, depth=2, max_nodes=500)), 5
    )
    out["query_ms"] = {
        "lookup_by_identifier": round(lookup_s * 1000, 2),
        "neighbours": round(neighbours_s * 1000 / 20, 2),
        "subgraph_depth_2": round(subgraph_s * 1000, 2),
    }

    graph, build_s, _ = timed(lambda: ctx.analytics.graph(tenant, refresh=True))
    overview, overview_s, _ = timed(lambda: ctx.analytics.overview(tenant, scope))
    _, paths_s, _ = timed(lambda: ctx.analytics.attack_paths(tenant, scope, limit=10))
    _, priorities_s, _ = timed(lambda: ctx.analytics.remediation_priorities(tenant, scope, limit=10))
    _, race_s, _ = timed(lambda: ctx.analytics.detection_race(tenant, scope))
    out["analytics"] = {
        "attack_graph": {"states": graph.state_count, "steps": graph.step_count},
        "build_projection_s": round(build_s, 2),
        "overview_s": round(overview_s, 2),
        "top_attack_paths_s": round(paths_s, 2),
        "remediation_priorities_s": round(priorities_s, 2),
        "detection_race_s": round(race_s, 2),
        "entry_points": overview["entry_points"],
        "targets": overview["targets"],
        "targets_at_risk": overview["targets_at_risk"],
    }
    try:
        import resource

        out["peak_memory_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    except ImportError:  # pragma: no cover - not available on Windows
        pass

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        load, reload, q, a = out["ingest_first_load"], out["ingest_unchanged_reload"], out["query_ms"], out["analytics"]
        lines = [
            f"Database: {db.dialect}    Python {out['machine']['python']}    {out['machine']['platform']}",
            f"Estate:   {args.assets:,} assets -> {out['estate']['nodes']:,} nodes, {out['estate']['edges']:,} edges",
            f"Ingest:   first load {load['seconds']} s ({load['records_per_s']:,} records/s, "
            f"{load['quarantined']} quarantined)",
            f"          unchanged reload {reload['seconds']} s ({reload['records_per_s']:,} records/s)",
            f"Queries:  lookup {q['lookup_by_identifier']} ms   neighbours {q['neighbours']} ms   "
            f"subgraph (depth 2) {q['subgraph_depth_2']} ms",
            f"Attack graph: {a['attack_graph']['states']:,} states, {a['attack_graph']['steps']:,} steps; "
            f"projection built in {a['build_projection_s']} s",
            f"          overview {a['overview_s']} s   top paths {a['top_attack_paths_s']} s   "
            f"priorities {a['remediation_priorities_s']} s   detection race {a['detection_race_s']} s",
            f"          {a['entry_points']} entry points, {a['targets_at_risk']} of {a['targets']} targets at risk",
        ]
        if "peak_memory_mb" in out:
            lines.append(f"Peak memory: {out['peak_memory_mb']} MB")
        print("\n".join(lines))
    db.dispose()
    scratch.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

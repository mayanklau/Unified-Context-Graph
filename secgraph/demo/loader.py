"""Load the demonstration estate through the same mappings and APIs a real deployment uses."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from secgraph.context import AppContext
from secgraph.governance.rbac import FULL_SCOPE, Principal
from secgraph.ingest.canonical import IngestRequest
from secgraph.ingest.pipeline import ingest_source
from secgraph.store.repository import GraphReader

# (file, mapping, parameters) — reference data first so findings resolve to full vulnerability records.
SOURCES: list[tuple[str, str, dict[str, str]]] = [
    ("nvd_cves.json", "nvd_cve", {}),
    ("kev.json", "cisa_kev", {}),
    ("epss.csv", "epss_csv", {}),
    ("attack.stix.json", "attack_stix", {}),
    ("assets.csv", "assets_csv", {}),
    ("identities.csv", "identities_csv", {}),
    ("scanner_findings.csv", "vuln_findings_csv", {}),
    ("web-portal-01.cdx.json", "cyclonedx", {"asset_fqdn": "web-portal-01.dmz.meridian.example"}),
    ("ocsf_vulnerability_findings.json", "ocsf_vulnerability_finding", {}),
    ("ocsf_detections.json", "ocsf_detection_finding", {}),
]


def read_source(name: str) -> str:
    return resources.files("secgraph.demo").joinpath("sources", name).read_text(encoding="utf-8")


def _resolve(ctx: AppContext, tenant_id: str, reference: dict[str, Any]) -> str | None:
    node_type = reference["type"]
    definition = ctx.ontology.node_types[node_type]
    with ctx.db.transaction() as session:
        for kind, value in reference["identifiers"].items():
            ident = definition.identifier(kind)
            if ident is None:
                continue
            from secgraph.ontology.normalize import normalize_identifier

            found = GraphReader(session, tenant_id).find_by_identifier(
                normalize_identifier(ident.normalize, kind, value), node_type=node_type, kind=kind
            )
            if found:
                return found[0]
    return None


def seed_demo(ctx: AppContext, tenant_id: str, principal: Principal) -> dict[str, Any]:
    """Populate ``tenant_id`` with the Meridian Bank estate. Safe to run again: ingestion is idempotent."""
    summary: dict[str, Any] = {"tenant": tenant_id, "sources": [], "memory_notes": 0}
    for file_name, mapping, params in SOURCES:
        result = ingest_source(
            ctx.ingest,
            ctx.mappings,
            ctx.settings,
            tenant_id,
            principal.id,
            mapping,
            read_source(file_name),
            params=params,
        )
        summary["sources"].append(
            {
                "file": file_name,
                "mapping": mapping,
                "nodes": result["nodes"],
                "edges": result["edges"],
                "quarantined": result["quarantined_total"],
            }
        )
    estate = json.loads(resources.files("secgraph.demo").joinpath("estate.json").read_text(encoding="utf-8"))
    outcome = ctx.ingest.ingest(tenant_id, principal.id, IngestRequest.model_validate(estate))
    summary["sources"].append(
        {
            "file": "estate.json",
            "mapping": None,
            "nodes": outcome.nodes.as_dict(),
            "edges": outcome.edges.as_dict(),
            "quarantined": len(outcome.rejections),
        }
    )
    summary["quarantined"] = sum(s["quarantined"] for s in summary["sources"])

    notes = json.loads(resources.files("secgraph.demo").joinpath("memory.json").read_text(encoding="utf-8"))["notes"]
    existing = {n["title"] for n in ctx.memory.search(tenant_id, FULL_SCOPE, limit=100)}
    for note in notes:
        if note["title"] in existing:
            continue
        entity_ids = [i for i in (_resolve(ctx, tenant_id, ref) for ref in note["entities"]) if i]
        created = ctx.memory.remember(
            tenant_id,
            principal,
            kind=note["kind"],
            title=note["title"],
            body=note["body"],
            entity_ids=entity_ids,
            tags=note.get("tags"),
            confidence=note.get("confidence"),
        )
        for result in note.get("outcomes", []):
            ctx.memory.feedback(tenant_id, principal, created["id"], result)
        summary["memory_notes"] += 1
    with ctx.db.transaction() as session:
        summary["graph"] = ctx.query.stats(session, tenant_id, FULL_SCOPE)
    return summary

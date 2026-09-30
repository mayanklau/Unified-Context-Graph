"""Source file → mapping → canonical batches → graph."""

from __future__ import annotations

from typing import Any

from secgraph.config import Settings
from secgraph.errors import ValidationFailed
from secgraph.ingest.canonical import SOURCE_RE
from secgraph.ingest.mapping import MappingRegistry
from secgraph.ingest.service import Counts, IngestService

_REPORTED = 100


def ingest_source(
    ingest: IngestService,
    mappings: MappingRegistry,
    settings: Settings,
    tenant_id: str,
    principal: str,
    mapping_name: str,
    payload: bytes | str | Any,
    *,
    params: dict[str, str] | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    """Translate a source-native payload with a named mapping and ingest it.

    Large files are ingested as several batches; the result aggregates them.
    """
    mapping = mappings.get(mapping_name)
    if source is not None:
        source = source.strip().lower()
        if not SOURCE_RE.match(source):
            raise ValidationFailed("source must be 1-64 characters of a-z, 0-9, '_', '.', ':' or '-'")
    nodes, edges = Counts(), Counts()
    summary: dict[str, Any] = {
        "mapping": mapping.name,
        "source": source or mapping.meta.source,
        "source_records": 0,
        "batches": [],
        "stubs_created": 0,
        "conflicts": 0,
        "quarantined_total": 0,
        "quarantined": [],
        "duration_ms": 0,
    }
    # Leave headroom: one source record can expand into several nodes and edges.
    per_batch = max(1, settings.ingest_max_records // 2)
    for batch in mapping.apply(payload, params, source=source, max_records=per_batch):
        result = ingest.ingest(tenant_id, principal, batch.request, mapping=mapping.name, source_errors=batch.errors)
        nodes.add(result.nodes)
        edges.add(result.edges)
        summary["source_records"] += batch.source_records + len(batch.errors)
        summary["batches"].append(result.batch_id)
        summary["stubs_created"] += result.stubs_created
        summary["conflicts"] += result.conflicts
        summary["quarantined_total"] += len(result.rejections)
        summary["duration_ms"] += result.duration_ms
        room = _REPORTED - len(summary["quarantined"])
        summary["quarantined"].extend(
            {"kind": r.kind, "index": r.index, "reason": r.reason} for r in result.rejections[: max(room, 0)]
        )
    summary["nodes"] = nodes.as_dict()
    summary["edges"] = edges.as_dict()
    return summary

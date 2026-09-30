"""API-facing views of nodes and edges, with personal-data masking applied."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from secgraph.governance.rbac import AccessScope
from secgraph.ontology.model import Ontology
from secgraph.store.records import EdgeRecord, NodeRecord

MASK = "***"


def iso(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if value is not None else None


def pseudonym(value: str) -> str:
    """Stable, non-reversible stand-in so masked values can still be correlated."""
    return "masked:" + hashlib.sha256(value.encode()).hexdigest()[:10]


class Viewer:
    """Turns store records into response dictionaries for one caller's scope."""

    def __init__(self, ontology: Ontology, scope: AccessScope):
        self.ontology = ontology
        self.scope = scope
        self._sensitive_props = ontology.sensitive_properties()
        self._sensitive_idents = ontology.sensitive_identifiers()
        self.masked_name_types: set[str] = set()
        for name, node_type in ontology.node_types.items():
            sensitive = self._sensitive_props.get(name, frozenset()) | self._sensitive_idents.get(name, frozenset())
            if sensitive & set(node_type.name_from):
                self.masked_name_types.add(name)

    def display_name(self, node_type: str, node_id: str, name: str) -> str:
        """The name this caller may see: personal names become a stable pseudonym when masked."""
        if not self.scope.pii and node_type in self.masked_name_types:
            return f"{node_type}-{hashlib.sha256(node_id.encode()).hexdigest()[:8]}"
        return name

    def node(self, record: NodeRecord, *, brief: bool = False) -> dict[str, Any]:
        masked = not self.scope.pii
        name = self.display_name(record.type, record.id, record.name)
        properties = record.properties
        if masked:
            hidden = self._sensitive_props.get(record.type)
            if hidden:
                properties = {k: (MASK if k in hidden else v) for k, v in properties.items()}
        view: dict[str, Any] = {"id": record.id, "type": record.type, "name": name}
        if brief:
            view["properties"] = properties
            if record.stub:
                view["stub"] = True
            return view
        view.update(
            properties=properties,
            stub=record.stub,
            confidence=record.confidence,
            version=record.version,
            valid_from=iso(record.valid_from),
            first_seen=iso(record.first_seen),
            last_seen=iso(record.last_seen),
            sources=record.sources,
        )
        if record.deleted:
            view["deleted"] = True
        if record.merged_into:
            view["merged_into"] = record.merged_into
        if record.identifiers is not None:
            view["identifiers"] = self.identifiers(record.type, record.identifiers)
        return view

    def identifiers(self, node_type: str, identifiers: dict[str, list[str]]) -> dict[str, list[str]]:
        if self.scope.pii:
            return identifiers
        hidden = self._sensitive_idents.get(node_type)
        if not hidden:
            return identifiers
        return {k: ([pseudonym(v) for v in values] if k in hidden else values) for k, values in identifiers.items()}

    def edge(self, record: EdgeRecord, *, brief: bool = False) -> dict[str, Any]:
        view: dict[str, Any] = {
            "id": record.id,
            "type": record.type,
            "source": record.source,
            "target": record.target,
            "properties": record.properties,
        }
        if record.key:
            view["key"] = record.key
        if brief:
            return view
        view.update(
            confidence=record.confidence,
            version=record.version,
            valid_from=iso(record.valid_from),
            valid_to=iso(record.valid_to),
            first_seen=iso(record.first_seen),
            last_seen=iso(record.last_seen),
            sources=record.sources,
        )
        return view

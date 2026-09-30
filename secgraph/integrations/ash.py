"""Connectors for the Agentic SOC Harness.

The harness hands its tools a bag of connectors (``ash.connectors.base``). These
two classes satisfy its ``AssetConnector`` and ``VulnerabilityConnector``
protocols by reading from the Security Graph, so every SOC agent built on the
harness works against the same graph without knowing it is there:

    from secgraph.client import SecurityGraphClient
    from secgraph.integrations.ash import GraphAssetConnector, GraphVulnerabilityConnector

    graph = SecurityGraphClient("https://graph.soc.local", api_key=...)
    connectors = Connectors(..., assets=GraphAssetConnector(graph), vulns=GraphVulnerabilityConnector(graph))

``asset_id`` may be a graph node id or anything the identity spine knows the
asset by: a host name, FQDN, IP address, EDR agent id or inventory id.
"""

from __future__ import annotations

from typing import Any

from secgraph.client import SecurityGraphClient, SecurityGraphError


def _resolve(graph: SecurityGraphClient, asset_id: str) -> dict[str, Any] | None:
    if len(asset_id) == 32 and all(c in "0123456789abcdef" for c in asset_id):
        try:
            return graph.get(asset_id)
        except SecurityGraphError as exc:
            if exc.status != 404:
                raise
    matches = [m for m in graph.lookup(asset_id) if m["type"] == "Asset"]
    return matches[0] if matches else None


class GraphAssetConnector:
    """``AssetConnector``: what the graph knows about an asset, including its attack exposure."""

    def __init__(self, graph: SecurityGraphClient, *, include_exposure: bool = True):
        self.graph = graph
        self.include_exposure = include_exposure

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        node = _resolve(self.graph, asset_id)
        if node is None:
            return {"asset_id": asset_id, "found": False}
        result: dict[str, Any] = {
            "asset_id": asset_id,
            "found": True,
            "graph_id": node["id"],
            "name": node["name"],
            "identifiers": node.get("identifiers", {}),
            **node["properties"],
        }
        if self.include_exposure:
            try:
                exposure = self.graph.exposure(node["id"])
            except SecurityGraphError:
                return result
            result["exposure"] = {
                "compromise_probability": exposure["compromise_probability"],
                "is_entry_point": exposure["is_entry_point"],
                "open_findings": exposure["open_finding_count"],
                "controls": [c["control_type"] for c in exposure["controls"]],
                "crown_jewels_reachable": [
                    {"name": t["name"], "type": t["type"], "path_probability": t["path_probability"]}
                    for t in exposure["targets_reachable"]
                ],
            }
        return result


class GraphVulnerabilityConnector:
    """``VulnerabilityConnector``: open findings on an asset, most exploitable first."""

    def __init__(self, graph: SecurityGraphClient):
        self.graph = graph

    def get_vulnerabilities(self, asset_id: str) -> dict[str, Any]:
        node = _resolve(self.graph, asset_id)
        if node is None:
            return {"asset_id": asset_id, "found": False, "vulnerabilities": []}
        try:
            exposure = self.graph.exposure(node["id"])
            findings = exposure["open_findings"]
        except SecurityGraphError:
            # No analytics permission: fall back to the raw relationships.
            matched = self.graph.match(
                {"start": {"id": node["id"]},
                 "steps": [{"edge": "HAS_FINDING", "node": {"type": "Finding"}},
                           {"edge": "INSTANCE_OF", "node": {"type": "Vulnerability"}}]}
            )
            findings = [
                {"finding_id": m["nodes"][1]["id"], "status": m["nodes"][1]["properties"].get("status"),
                 "vulnerability": m["nodes"][2]["name"], "kev": m["nodes"][2]["properties"].get("kev", False),
                 "epss": m["nodes"][2]["properties"].get("epss"),
                 "cvss_score": m["nodes"][2]["properties"].get("cvss_score")}
                for m in matched["matches"]
            ]
        return {
            "asset_id": asset_id,
            "found": True,
            "graph_id": node["id"],
            "count": len(findings),
            "known_exploited": sum(1 for f in findings if f.get("kev")),
            "vulnerabilities": findings,
        }

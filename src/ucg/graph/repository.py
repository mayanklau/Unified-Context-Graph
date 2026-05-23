from collections import deque
from datetime import UTC, datetime
from typing import Protocol

from ucg.graph.models import GraphContext, GraphEdge, GraphNode


class GraphRepository(Protocol):
    def upsert_node(self, node: GraphNode) -> GraphNode: ...

    def upsert_edge(self, edge: GraphEdge) -> GraphEdge: ...

    def get_node(self, node_id: str, tenant_id: str) -> GraphNode | None: ...

    def context(self, node_id: str, tenant_id: str, depth: int) -> GraphContext: ...

    def nodes(self, tenant_id: str) -> list[GraphNode]: ...


class InMemoryGraphRepository:
    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], GraphNode] = {}
        self._edges: dict[tuple[str, str], GraphEdge] = {}

    def upsert_node(self, node: GraphNode) -> GraphNode:
        key = (node.tenant_id, node.id)
        existing = self._nodes.get(key)
        if existing:
            merged_sources = sorted({*existing.sources, *node.sources})
            merged = existing.model_copy(
                update={
                    "name": node.name or existing.name,
                    "type": node.type,
                    "attributes": {**existing.attributes, **node.attributes},
                    "sources": merged_sources,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._nodes[key] = merged
            return merged
        self._nodes[key] = node
        return node

    def upsert_edge(self, edge: GraphEdge) -> GraphEdge:
        self._edges[(edge.tenant_id, edge.id)] = edge
        return edge

    def get_node(self, node_id: str, tenant_id: str) -> GraphNode | None:
        return self._nodes.get((tenant_id, node_id))

    def nodes(self, tenant_id: str) -> list[GraphNode]:
        return [node for (node_tenant, _), node in self._nodes.items() if node_tenant == tenant_id]

    def context(self, node_id: str, tenant_id: str, depth: int) -> GraphContext:
        if self.get_node(node_id, tenant_id) is None:
            return GraphContext(root_id=node_id, depth=depth, nodes=[], edges=[])

        visited_nodes = {node_id}
        visited_edges: dict[str, GraphEdge] = {}
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            for edge in self._tenant_edges(tenant_id):
                if edge.source_id != current_id and edge.target_id != current_id:
                    continue
                visited_edges[edge.id] = edge
                neighbor_id = edge.target_id if edge.source_id == current_id else edge.source_id
                if neighbor_id not in visited_nodes:
                    visited_nodes.add(neighbor_id)
                    queue.append((neighbor_id, current_depth + 1))

        nodes = [
            node
            for node_ref in visited_nodes
            if (node := self.get_node(node_ref, tenant_id)) is not None
        ]
        return GraphContext(
            root_id=node_id,
            depth=depth,
            nodes=sorted(nodes, key=lambda node: node.id),
            edges=sorted(visited_edges.values(), key=lambda edge: edge.id),
        )

    def _tenant_edges(self, tenant_id: str) -> list[GraphEdge]:
        return [edge for (edge_tenant, _), edge in self._edges.items() if edge_tenant == tenant_id]

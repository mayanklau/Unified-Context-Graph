"""Graph queries.

Every query is bounded: depth, fan-out and result size have hard limits from
configuration, and a query that hits one says so (``truncated``) instead of
silently returning part of the answer.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from secgraph.config import Settings
from secgraph.errors import NotFound, PermissionDenied, ValidationFailed
from secgraph.governance.rbac import AccessScope
from secgraph.observability import QUERY_SECONDS, timed
from secgraph.ontology.model import Ontology
from secgraph.ontology.normalize import normalize_identifier
from secgraph.ontology.validate import matches, validate_predicate
from secgraph.query.views import Viewer
from secgraph.store.records import EdgeRecord, NodeRecord
from secgraph.store.repository import GraphReader


class QueryService:
    def __init__(self, ontology: Ontology, settings: Settings):
        self.ontology = ontology
        self.settings = settings
        self._all_types = list(ontology.node_types)
        self._list_props = frozenset(
            name
            for node_type in ontology.node_types.values()
            for name, definition in node_type.properties.items()
            if definition.type == "string_list"
        )

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _limit(self, limit: int | None) -> int:
        if limit is None:
            return self.settings.query_default_limit
        if limit < 1:
            raise ValidationFailed("limit must be at least 1")
        return min(limit, self.settings.query_max_limit)

    def _check_types(self, node_types: Sequence[str] | None, edge_types: Sequence[str] | None) -> None:
        for t in node_types or ():
            if t not in self.ontology.node_types:
                raise ValidationFailed(f"unknown node type '{t}'")
        for t in edge_types or ():
            if t not in self.ontology.edge_types:
                raise ValidationFailed(f"unknown edge type '{t}'")

    def _check_where(self, where: Mapping[str, Any] | None, types: Sequence[str] | None, scope: AccessScope) -> None:
        if not where:
            return
        validate_predicate(where)
        if scope.pii:
            return
        sensitive = self.ontology.sensitive_properties()
        for type_name in types or self._all_types:
            blocked = sensitive.get(type_name, frozenset()) & set(where)
            if blocked:
                raise PermissionDenied(
                    f"filtering on {type_name}.{sorted(blocked)[0]} needs the 'pii:read' permission"
                )

    def _visible(self, records: Mapping[str, NodeRecord], scope: AccessScope) -> dict[str, NodeRecord]:
        if scope.unrestricted:
            return dict(records)
        return {i: r for i, r in records.items() if scope.allows(r.type)}

    def _require_node(
        self, reader: GraphReader, node_id: str, scope: AccessScope, as_of: datetime | None = None
    ) -> NodeRecord:
        resolved = reader.resolve_id(node_id) if as_of is None else node_id
        record = reader.get_node(resolved, as_of=as_of)
        if record is None or not scope.allows(record.type):
            raise NotFound(f"node {node_id} does not exist")
        return record

    # ------------------------------------------------------------------ #
    # lookup
    # ------------------------------------------------------------------ #
    def get_node(
        self, session: Session, tenant_id: str, node_id: str, scope: AccessScope, *, as_of: datetime | None = None
    ) -> dict[str, Any]:
        with timed(QUERY_SECONDS, operation="get_node"):
            reader = GraphReader(session, tenant_id)
            record = self._require_node(reader, node_id, scope, as_of)
            record.identifiers = reader.identifiers_for([record.id]).get(record.id, {})
            view = Viewer(self.ontology, scope).node(record)
            if as_of is None:
                view["degree"] = reader.edge_counts(record.id)
            if record.id != node_id:
                view["requested_id"] = node_id  # the requested node was merged into this one
            return view

    def find_by_identifier(
        self,
        session: Session,
        tenant_id: str,
        scope: AccessScope,
        *,
        value: str,
        node_type: str | None = None,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Exact lookup through the identity spine.

        With ``node_type`` and ``kind`` the value is normalised exactly as ingestion
        normalises it; otherwise it is tried as given and then lower-cased.
        """
        self._check_types([node_type] if node_type else None, None)
        needle = value.strip()
        if not needle or len(needle) > 512:
            raise ValidationFailed("value must be 1-512 characters")
        candidates = [needle]
        if node_type and kind:
            definition = self.ontology.node_types[node_type].identifier(kind)
            if definition is None:
                raise ValidationFailed(f"{node_type} has no identifier '{kind}'")
            if definition.sensitive and not scope.pii:
                raise PermissionDenied(f"looking up by {node_type}.{kind} needs the 'pii:read' permission")
            candidates = [normalize_identifier(definition.normalize, kind, needle)]
        elif needle.lower() != needle:
            candidates.append(needle.lower())
        hidden = {} if scope.pii else self.ontology.sensitive_identifiers()
        with timed(QUERY_SECONDS, operation="find_by_identifier"):
            reader = GraphReader(session, tenant_id)
            ids: list[str] = []
            for candidate in candidates:
                for node_id, found_type, found_kind in reader.find_aliases(candidate, node_type=node_type, kind=kind):
                    if found_kind in hidden.get(found_type, ()):
                        continue  # a masked caller must not be able to confirm personal identifiers
                    if node_id not in ids:
                        ids.append(node_id)
                if ids:
                    break
            records = self._visible(reader.get_nodes(ids), scope)
            viewer = Viewer(self.ontology, scope)
            return [viewer.node(r) for r in records.values()]

    def search(
        self,
        session: Session,
        tenant_id: str,
        scope: AccessScope,
        *,
        types: Sequence[str] | None = None,
        text: str | None = None,
        where: Mapping[str, Any] | None = None,
        include_stubs: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._check_types(types, None)
        if offset < 0:
            raise ValidationFailed("offset must not be negative")
        if text is not None and len(text) > 256:
            raise ValidationFailed("search text is limited to 256 characters")
        effective = scope.restrict(list(types) if types else None, self._all_types)
        self._check_where(where, effective, scope)
        viewer = Viewer(self.ontology, scope)
        if text and not scope.pii:
            # Free-text search over personal names/identifiers would be an oracle for masked data.
            searchable = [t for t in (effective or self._all_types) if t not in viewer._mask_name]
            effective = searchable
        page = self._limit(limit)
        with timed(QUERY_SECONDS, operation="search"):
            reader = GraphReader(session, tenant_id)
            records, total = reader.search_nodes(
                types=effective,
                text=text,
                where=where,
                list_properties=self._list_props,
                include_stubs=include_stubs,
                limit=page,
                offset=offset,
            )
        return {
            "items": [viewer.node(r, brief=True) for r in records],
            "total": total,
            "limit": page,
            "offset": offset,
        }

    def history(self, session: Session, tenant_id: str, node_id: str, scope: AccessScope) -> list[dict[str, Any]]:
        reader = GraphReader(session, tenant_id)
        current = reader.get_node(reader.resolve_id(node_id), include_deleted=True)
        if current is None or not scope.allows(current.type):
            raise NotFound(f"node {node_id} does not exist")
        viewer = Viewer(self.ontology, scope)
        out = []
        for version in reader.node_history(current.id):
            shell = NodeRecord(id=current.id, type=current.type, name=version["name"], properties=version["properties"])
            masked = viewer.node(shell, brief=True)
            out.append(
                {
                    "version": version["version"],
                    "valid_from": version["valid_from"].isoformat(),
                    "valid_to": version["valid_to"].isoformat() if version["valid_to"] else None,
                    "name": masked["name"],
                    "properties": masked["properties"],
                    "stub": version["stub"],
                    "deleted": version["deleted"],
                    "changed_by": version["changed_by"],
                }
            )
        return out

    # ------------------------------------------------------------------ #
    # neighbourhood
    # ------------------------------------------------------------------ #
    def neighbors(
        self,
        session: Session,
        tenant_id: str,
        node_id: str,
        scope: AccessScope,
        *,
        direction: str = "both",
        edge_types: Sequence[str] | None = None,
        node_types: Sequence[str] | None = None,
        limit: int | None = None,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        self._check_types(node_types, edge_types)
        page = self._limit(limit)
        with timed(QUERY_SECONDS, operation="neighbors"):
            reader = GraphReader(session, tenant_id)
            center = self._require_node(reader, node_id, scope, as_of)
            edges, truncated = reader.edges_of(
                [center.id], direction=direction, types=edge_types, as_of=as_of, limit=page
            )
            other_ids = [e.target if e.source == center.id else e.source for e in edges]
            others = self._visible(reader.get_nodes(other_ids, as_of=as_of), scope)
            if node_types:
                wanted = set(node_types)
                others = {i: r for i, r in others.items() if r.type in wanted}
            viewer = Viewer(self.ontology, scope)
            items = []
            for edge in edges:
                other_id = edge.target if edge.source == center.id else edge.source
                other = others.get(other_id)
                if other is None:
                    continue
                items.append(
                    {
                        "edge": viewer.edge(edge, brief=True),
                        "direction": "out" if edge.source == center.id else "in",
                        "node": viewer.node(other, brief=True),
                    }
                )
            return {"node": viewer.node(center, brief=True), "neighbors": items, "truncated": truncated}

    def subgraph(
        self,
        session: Session,
        tenant_id: str,
        seeds: Sequence[str],
        scope: AccessScope,
        *,
        depth: int = 1,
        direction: str = "both",
        edge_types: Sequence[str] | None = None,
        max_nodes: int | None = None,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Breadth-first expansion from the seeds, ``depth`` hops out."""
        self._check_types(None, edge_types)
        if not seeds:
            raise ValidationFailed("at least one seed node is required")
        if len(seeds) > 100:
            raise ValidationFailed("at most 100 seed nodes")
        if not 0 <= depth <= self.settings.query_max_depth:
            raise ValidationFailed(f"depth must be between 0 and {self.settings.query_max_depth}")
        cap = min(max_nodes or self.settings.query_max_nodes, self.settings.query_max_nodes)
        with timed(QUERY_SECONDS, operation="subgraph"):
            reader = GraphReader(session, tenant_id)
            resolved = [reader.resolve_id(s) if as_of is None else s for s in seeds]
            nodes = self._visible(reader.get_nodes(resolved, as_of=as_of), scope)
            missing = [s for s, r in zip(seeds, resolved, strict=True) if r not in nodes]
            if missing:
                raise NotFound(f"node {missing[0]} does not exist")
            edges: dict[str, EdgeRecord] = {}
            frontier = list(nodes)
            truncated = False
            for _hop in range(depth):
                if not frontier:
                    break
                budget = max(cap * 4, 1000)
                found, cut = reader.edges_of(
                    frontier, direction=direction, types=edge_types, as_of=as_of, limit=budget
                )
                truncated = truncated or cut
                new_ids = []
                for edge in found:
                    for end in (edge.source, edge.target):
                        if end not in nodes:
                            new_ids.append(end)
                fetched = self._visible(reader.get_nodes(list(dict.fromkeys(new_ids)), as_of=as_of), scope)
                next_frontier = []
                for node_id, record in fetched.items():
                    if len(nodes) >= cap:
                        truncated = True
                        break
                    nodes[node_id] = record
                    next_frontier.append(node_id)
                for edge in found:
                    if edge.source in nodes and edge.target in nodes:
                        edges[edge.id] = edge
                frontier = next_frontier
            viewer = Viewer(self.ontology, scope)
            return {
                "nodes": [viewer.node(r, brief=True) for r in nodes.values()],
                "edges": [viewer.edge(e, brief=True) for e in edges.values()],
                "truncated": truncated,
            }

    # ------------------------------------------------------------------ #
    # paths
    # ------------------------------------------------------------------ #
    def shortest_path(
        self,
        session: Session,
        tenant_id: str,
        source_id: str,
        target_id: str,
        scope: AccessScope,
        *,
        max_depth: int | None = None,
        edge_types: Sequence[str] | None = None,
        directed: bool = False,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Fewest-hops path between two nodes (bidirectional breadth-first search)."""
        self._check_types(None, edge_types)
        limit_depth = self.settings.query_max_depth if max_depth is None else max_depth
        if not 1 <= limit_depth <= self.settings.query_max_depth:
            raise ValidationFailed(f"max_depth must be between 1 and {self.settings.query_max_depth}")
        with timed(QUERY_SECONDS, operation="shortest_path"):
            reader = GraphReader(session, tenant_id)
            source = self._require_node(reader, source_id, scope, as_of)
            target = self._require_node(reader, target_id, scope, as_of)
            viewer = Viewer(self.ontology, scope)
            if source.id == target.id:
                return {"found": True, "length": 0, "nodes": [viewer.node(source, brief=True)], "edges": []}

            # parent maps: node -> (previous node, edge) on each side
            parents: tuple[dict[str, tuple[str, EdgeRecord] | None], dict[str, tuple[str, EdgeRecord] | None]] = (
                {source.id: None},
                {target.id: None},
            )
            frontiers: list[list[str]] = [[source.id], [target.id]]
            visited_budget = self.settings.query_max_nodes * 4
            fan_out = max(self.settings.query_max_nodes * 4, 2000)
            meet: str | None = None
            truncated = False
            depth_used = 0
            while depth_used < limit_depth and frontiers[0] and frontiers[1] and meet is None:
                side = 0 if len(frontiers[0]) <= len(frontiers[1]) else 1
                if directed:
                    direction = "out" if side == 0 else "in"
                else:
                    direction = "both"
                found, cut = reader.edges_of(
                    frontiers[side], direction=direction, types=edge_types, as_of=as_of, limit=fan_out
                )
                truncated = truncated or cut
                frontier_set = set(frontiers[side])
                candidates: dict[str, tuple[str, EdgeRecord]] = {}
                for edge in found:
                    for here, there in ((edge.source, edge.target), (edge.target, edge.source)):
                        if here not in frontier_set or there in parents[side] or there in candidates:
                            continue
                        if directed and ((side == 0 and here != edge.source) or (side == 1 and here != edge.target)):
                            continue
                        candidates[there] = (here, edge)
                allowed = self._visible(reader.get_nodes(list(candidates), as_of=as_of), scope)
                next_frontier = []
                for node_id in candidates:
                    if node_id not in allowed:
                        continue
                    parents[side][node_id] = candidates[node_id]
                    next_frontier.append(node_id)
                    if node_id in parents[1 - side]:
                        meet = node_id
                        break
                frontiers[side] = next_frontier
                depth_used += 1
                if len(parents[0]) + len(parents[1]) > visited_budget:
                    truncated = True
                    break
            if meet is None:
                return {"found": False, "length": None, "nodes": [], "edges": [], "truncated": truncated}

            left_nodes: list[str] = []
            left_edges: list[EdgeRecord] = []
            cursor: str = meet
            while parents[0][cursor] is not None:
                previous, edge = parents[0][cursor]  # type: ignore[misc]
                left_nodes.append(cursor)
                left_edges.append(edge)
                cursor = previous
            path_nodes = [source.id, *reversed(left_nodes)]
            path_edges = list(reversed(left_edges))
            cursor = meet
            while parents[1][cursor] is not None:
                following, edge = parents[1][cursor]  # type: ignore[misc]
                path_nodes.append(following)
                path_edges.append(edge)
                cursor = following
            records = reader.get_nodes(path_nodes, as_of=as_of)
            return {
                "found": True,
                "length": len(path_edges),
                "nodes": [viewer.node(records[i], brief=True) for i in path_nodes if i in records],
                "edges": [viewer.edge(e, brief=True) for e in path_edges],
                "truncated": truncated,
            }

    # ------------------------------------------------------------------ #
    # pattern matching
    # ------------------------------------------------------------------ #
    def match(
        self,
        session: Session,
        tenant_id: str,
        pattern: Mapping[str, Any],
        scope: AccessScope,
        *,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Match a linear path pattern.

        ``{"start": {"type": "Asset", "where": {"internet_exposed": true}},
           "steps": [{"edge": "HAS_FINDING", "direction": "out",
                      "node": {"type": "Finding", "where": {"status": "open"}}}],
           "limit": 100}``
        """
        start = pattern.get("start")
        steps = pattern.get("steps", [])
        if not isinstance(start, Mapping) or not isinstance(steps, list):
            raise ValidationFailed("a pattern needs 'start' (object) and 'steps' (list)")
        unknown = set(pattern) - {"start", "steps", "limit"}
        if unknown:
            raise ValidationFailed(f"unknown pattern key(s): {', '.join(sorted(unknown))}")
        if len(steps) > self.settings.query_max_depth:
            raise ValidationFailed(f"a pattern may have at most {self.settings.query_max_depth} steps")
        limit = self._limit(pattern.get("limit"))

        def node_spec(spec: Any, where_label: str) -> tuple[list[str] | None, Mapping[str, Any]]:
            if spec is None:
                return None, {}
            if not isinstance(spec, Mapping) or set(spec) - {"type", "types", "where", "id"}:
                raise ValidationFailed(f"{where_label}: expected an object with 'type', 'types', 'where' or 'id'")
            types = spec.get("types") or ([spec["type"]] if spec.get("type") else None)
            if types is not None and (not isinstance(types, list) or not all(isinstance(t, str) for t in types)):
                raise ValidationFailed(f"{where_label}: 'types' must be a list of node type names")
            where = spec.get("where") or {}
            if not isinstance(where, Mapping):
                raise ValidationFailed(f"{where_label}: 'where' must be an object")
            self._check_types(types, None)
            self._check_where(where, types, scope)
            return types, where

        start_types, start_where = node_spec(start, "start")
        parsed_steps: list[tuple[list[str] | None, str, list[str] | None, Mapping[str, Any], Mapping[str, Any]]] = []
        for index, step in enumerate(steps):
            if not isinstance(step, Mapping) or set(step) - {"edge", "edges", "direction", "node", "where"}:
                raise ValidationFailed(f"steps[{index}]: expected 'edge', 'direction', 'node' and optional 'where'")
            edge_types = step.get("edges") or ([step["edge"]] if step.get("edge") else None)
            if edge_types is not None and not isinstance(edge_types, list):
                raise ValidationFailed(f"steps[{index}]: 'edges' must be a list")
            self._check_types(None, edge_types)
            direction = step.get("direction", "out")
            if direction not in ("out", "in", "both"):
                raise ValidationFailed(f"steps[{index}]: direction must be out, in or both")
            edge_where = step.get("where") or {}
            if not isinstance(edge_where, Mapping):
                raise ValidationFailed(f"steps[{index}]: 'where' must be an object")
            validate_predicate(edge_where)
            node_types, node_where = node_spec(step.get("node"), f"steps[{index}].node")
            parsed_steps.append((edge_types, direction, node_types, node_where, edge_where))

        cap = self.settings.query_max_nodes
        with timed(QUERY_SECONDS, operation="match"):
            reader = GraphReader(session, tenant_id)
            truncated = False
            if isinstance(start.get("id"), str):
                record = self._require_node(reader, start["id"], scope, as_of)
                starts = [record] if (not start_types or record.type in start_types) else []
                starts = [r for r in starts if matches(r.properties, start_where)]
            else:
                effective = scope.restrict(start_types, self._all_types)
                starts, total = reader.search_nodes(
                    types=effective, where=start_where, list_properties=self._list_props, limit=cap
                )
                truncated = total > len(starts)
            known: dict[str, NodeRecord] = {r.id: r for r in starts}
            # each partial path: (node ids, edge records)
            paths: deque[tuple[tuple[str, ...], tuple[EdgeRecord, ...]]] = deque(((r.id,), ()) for r in starts)
            for edge_types, direction, node_types, node_where, edge_where in parsed_steps:
                if not paths:
                    break
                tails = list(dict.fromkeys(p[0][-1] for p in paths))
                found, cut = reader.edges_of(
                    tails, direction=direction, types=edge_types, as_of=as_of, limit=cap * 4, where=edge_where or None
                )
                truncated = truncated or cut
                by_tail: dict[str, list[tuple[str, EdgeRecord]]] = {}
                for edge in found:
                    if direction in ("out", "both"):
                        by_tail.setdefault(edge.source, []).append((edge.target, edge))
                    if direction in ("in", "both"):
                        by_tail.setdefault(edge.target, []).append((edge.source, edge))
                wanted_ids = list(dict.fromkeys(other for pairs in by_tail.values() for other, _e in pairs))
                fetched = self._visible(
                    reader.get_nodes([i for i in wanted_ids if i not in known], as_of=as_of), scope
                )
                known.update(fetched)
                type_set = set(node_types) if node_types else None
                extended: deque[tuple[tuple[str, ...], tuple[EdgeRecord, ...]]] = deque()
                for node_ids, path_edges in paths:
                    for other, edge in by_tail.get(node_ids[-1], ()):
                        record = known.get(other)
                        if record is None or other in node_ids:
                            continue
                        if type_set is not None and record.type not in type_set:
                            continue
                        if node_where and not matches(record.properties, node_where):
                            continue
                        if len(extended) >= cap:
                            truncated = True
                            break
                        extended.append(((*node_ids, other), (*path_edges, edge)))
                paths = extended
            viewer = Viewer(self.ontology, scope)
            total_matches = len(paths)
            rows = []
            for node_ids, path_edges in list(paths)[:limit]:
                rows.append(
                    {
                        "nodes": [viewer.node(known[i], brief=True) for i in node_ids],
                        "edges": [viewer.edge(e, brief=True) for e in path_edges],
                    }
                )
            return {"matches": rows, "count": total_matches, "truncated": truncated or total_matches > limit}

    # ------------------------------------------------------------------ #
    # statistics
    # ------------------------------------------------------------------ #
    def stats(self, session: Session, tenant_id: str, scope: AccessScope) -> dict[str, Any]:
        reader = GraphReader(session, tenant_id)
        nodes = {t: c for t, c in reader.count_nodes_by_type().items() if scope.allows(t)}
        edges = reader.count_edges_by_type() if scope.unrestricted else {}
        return {
            "nodes": dict(sorted(nodes.items())),
            "edges": dict(sorted(edges.items())),
            "node_total": sum(nodes.values()),
            "edge_total": sum(edges.values()),
            "ontology": {"name": self.ontology.name, "version": self.ontology.version},
        }

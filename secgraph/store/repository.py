"""Read side of the graph store.

All reads go through :class:`GraphReader`, which pins the tenant and, when
asked, a point in time. It returns plain records (see ``records.py``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Numeric, String, and_, case, cast, func, literal, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from secgraph.errors import ValidationFailed
from secgraph.store.models import Edge, Node, NodeAlias, NodeVersion
from secgraph.store.records import EdgeRecord, NodeRecord

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}$")
_CHUNK = 900  # stay below SQLite's bound-parameter limit


def chunked(items: Sequence[Any], size: int = _CHUNK) -> Iterator[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def node_record(row: Node) -> NodeRecord:
    return NodeRecord(
        id=row.id,
        type=row.type,
        name=row.name,
        properties=dict(row.properties or {}),
        stub=row.stub,
        confidence=row.confidence,
        version=row.version,
        valid_from=row.valid_from,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        sources=dict(row.sources or {}),
        deleted=row.deleted_at is not None,
        merged_into=row.merged_into,
    )


def edge_record(row: Edge) -> EdgeRecord:
    return EdgeRecord(
        id=row.lineage_id,
        type=row.type,
        source=row.src_id,
        target=row.dst_id,
        key=row.edge_key,
        properties=dict(row.properties or {}),
        confidence=row.confidence,
        version=row.version,
        valid_from=row.valid_from,
        valid_to=row.valid_to,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        sources=dict(row.sources or {}),
    )


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class PropertyFilter:
    """Translate a ``where`` predicate on node/edge properties into SQL for the active dialect."""

    def __init__(self, dialect: str, list_properties: frozenset[str] = frozenset()):
        self.dialect = dialect
        self.list_properties = list_properties

    def build(self, column: Any, where: Mapping[str, Any]) -> list[ColumnElement[bool]]:
        clauses: list[ColumnElement[bool]] = []
        for key, condition in where.items():
            if not isinstance(key, str) or not _KEY_RE.match(key):
                raise ValidationFailed(f"invalid property name in filter: {key!r}")
            if isinstance(condition, Mapping):
                for op, expected in condition.items():
                    clauses.append(self._clause(column, key, op, expected))
            else:
                clauses.append(self._clause(column, key, "eq", condition))
        return clauses

    # -- helpers ---------------------------------------------------------- #
    def _scalar(self, value: Any, op: str) -> Any:
        if isinstance(value, bool | int | float | str) or value is None:
            return value
        raise ValidationFailed(f"filter operator '{op}' needs a scalar value")

    def _pg_contains(self, column: Any, payload: dict[str, Any]) -> ColumnElement[bool]:
        return column.op("@>")(cast(literal(json.dumps(payload)), JSONB))

    def _sqlite_value(self, column: Any, key: str) -> Any:
        return func.json_extract(column, f'$."{key}"')

    def _pg_numeric(self, column: Any, key: str) -> Any:
        return case(
            (func.jsonb_typeof(column.op("->")(key)) == "number", cast(column.op("->>")(key), Numeric)),
            else_=None,
        )

    def _clause(self, column: Any, key: str, op: str, expected: Any) -> ColumnElement[bool]:
        pg = self.dialect == "postgresql"
        if op == "eq":
            value = self._scalar(expected, op)
            if value is None:
                return self._clause(column, key, "exists", False)
            if pg:
                return self._pg_contains(column, {key: value})
            if isinstance(value, bool):
                return self._sqlite_value(column, key) == (1 if value else 0)
            return self._sqlite_value(column, key) == value
        if op == "ne":
            return or_(~self._clause(column, key, "eq", expected), self._clause(column, key, "exists", False))
        if op == "exists":
            present = column.op("->")(key).is_not(None) if pg else self._sqlite_value(column, key).is_not(None)
            return present if expected else ~present
        if op in ("in", "nin"):
            if not isinstance(expected, list | tuple) or not expected:
                raise ValidationFailed(f"filter operator '{op}' needs a non-empty list")
            if len(expected) > 100:
                raise ValidationFailed(f"filter operator '{op}' accepts at most 100 values")
            any_of = or_(*[self._clause(column, key, "eq", v) for v in expected])
            return any_of if op == "in" else or_(~any_of, self._clause(column, key, "exists", False))
        if op in ("gt", "gte", "lt", "lte"):
            if isinstance(expected, bool) or not isinstance(expected, int | float | str):
                raise ValidationFailed(f"filter operator '{op}' needs a number or an ISO timestamp")
            if isinstance(expected, str):  # ISO-8601 UTC timestamps sort lexicographically
                left: Any = column.op("->>")(key) if pg else self._sqlite_value(column, key)
            else:
                left = self._pg_numeric(column, key) if pg else self._sqlite_value(column, key)
            return {"gt": left > expected, "gte": left >= expected, "lt": left < expected, "lte": left <= expected}[op]
        if op == "contains":
            if not isinstance(expected, str) or not expected:
                raise ValidationFailed("filter operator 'contains' needs a non-empty string")
            if key in self.list_properties:
                if pg:
                    return self._pg_contains(column, {key: [expected]})
                each = func.json_each(column, f'$."{key}"').table_valued("value")
                return select(literal(1)).select_from(each).where(each.c.value == expected).exists()
            pattern = f"%{_like_escape(expected.lower())}%"
            text_value = column.op("->>")(key) if pg else cast(self._sqlite_value(column, key), String)
            return func.lower(text_value).like(pattern, escape="\\")
        raise ValidationFailed(f"unknown filter operator '{op}'")


class GraphReader:
    def __init__(self, session: Session, tenant_id: str):
        self.session = session
        self.tenant_id = tenant_id
        self.dialect = session.get_bind().dialect.name

    # ------------------------------------------------------------------ #
    # Nodes
    # ------------------------------------------------------------------ #
    def resolve_id(self, node_id: str) -> str:
        """Follow merge redirects so ids handed out before a merge keep working."""
        seen: set[str] = set()
        current = node_id
        while current not in seen:
            seen.add(current)
            merged = self.session.execute(
                select(Node.merged_into).where(Node.tenant_id == self.tenant_id, Node.id == current)
            ).scalar_one_or_none()
            if not merged:
                return current
            current = merged
        return current

    def get_nodes(
        self, ids: Iterable[str], *, as_of: datetime | None = None, include_deleted: bool = False
    ) -> dict[str, NodeRecord]:
        wanted = list(dict.fromkeys(ids))
        out: dict[str, NodeRecord] = {}
        historical: list[str] = []
        for chunk in chunked(wanted):
            rows = self.session.execute(
                select(Node).where(Node.tenant_id == self.tenant_id, Node.id.in_(chunk))
            ).scalars()
            for row in rows:
                if as_of is None:
                    if row.deleted_at is None or include_deleted:
                        out[row.id] = node_record(row)
                elif row.created_at > as_of:
                    continue
                elif row.valid_from <= as_of:
                    if row.deleted_at is None or include_deleted:
                        out[row.id] = node_record(row)
                else:
                    historical.append(row.id)
        if as_of is not None and historical:
            out.update(self._versions_at(historical, as_of, include_deleted))
        return out

    def _versions_at(self, ids: Sequence[str], as_of: datetime, include_deleted: bool) -> dict[str, NodeRecord]:
        out: dict[str, NodeRecord] = {}
        for chunk in chunked(ids):
            versions = self.session.execute(
                select(NodeVersion).where(
                    NodeVersion.tenant_id == self.tenant_id,
                    NodeVersion.node_id.in_(chunk),
                    NodeVersion.valid_from <= as_of,
                    NodeVersion.valid_to > as_of,
                )
            ).scalars()
            for v in versions:
                if v.deleted and not include_deleted:
                    continue
                out[v.node_id] = NodeRecord(
                    id=v.node_id,
                    type=v.type,
                    name=v.name,
                    properties=dict(v.properties or {}),
                    stub=v.stub,
                    version=v.version,
                    valid_from=v.valid_from,
                    deleted=v.deleted,
                )
        return out

    def get_node(
        self, node_id: str, *, as_of: datetime | None = None, include_deleted: bool = False
    ) -> NodeRecord | None:
        return self.get_nodes([node_id], as_of=as_of, include_deleted=include_deleted).get(node_id)

    def identifiers_for(self, node_ids: Sequence[str]) -> dict[str, dict[str, list[str]]]:
        out: dict[str, dict[str, list[str]]] = {nid: {} for nid in node_ids}
        for chunk in chunked(list(node_ids)):
            rows = self.session.execute(
                select(NodeAlias.node_id, NodeAlias.kind, NodeAlias.value)
                .where(NodeAlias.tenant_id == self.tenant_id, NodeAlias.node_id.in_(chunk))
                .order_by(NodeAlias.kind, NodeAlias.value)
            )
            for node_id, kind, value in rows:
                out.setdefault(node_id, {}).setdefault(kind, []).append(value)
        return out

    def find_by_identifier(
        self, value: str, *, node_type: str | None = None, kind: str | None = None, limit: int = 50
    ) -> list[str]:
        stmt = select(NodeAlias.node_id).where(NodeAlias.tenant_id == self.tenant_id, NodeAlias.value == value)
        if node_type:
            stmt = stmt.where(NodeAlias.node_type == node_type)
        if kind:
            stmt = stmt.where(NodeAlias.kind == kind)
        return list(dict.fromkeys(self.session.execute(stmt.limit(limit)).scalars()))

    def find_aliases(
        self, value: str, *, node_type: str | None = None, kind: str | None = None, limit: int = 50
    ) -> list[tuple[str, str, str]]:
        """``(node_id, node_type, kind)`` for every alias with exactly this value."""
        stmt = select(NodeAlias.node_id, NodeAlias.node_type, NodeAlias.kind).where(
            NodeAlias.tenant_id == self.tenant_id, NodeAlias.value == value
        )
        if node_type:
            stmt = stmt.where(NodeAlias.node_type == node_type)
        if kind:
            stmt = stmt.where(NodeAlias.kind == kind)
        return [(n, t, k) for n, t, k in self.session.execute(stmt.limit(limit))]

    def search_nodes(
        self,
        *,
        types: Sequence[str] | None = None,
        text: str | None = None,
        where: Mapping[str, Any] | None = None,
        list_properties: frozenset[str] = frozenset(),
        include_stubs: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[NodeRecord], int]:
        """Current-state search. Returns ``(page, total)``."""
        conditions: list[ColumnElement[bool]] = [Node.tenant_id == self.tenant_id, Node.deleted_at.is_(None)]
        if types is not None:
            if not types:
                return [], 0
            conditions.append(Node.type.in_(list(types)))
        if not include_stubs:
            conditions.append(Node.stub.is_(False))
        if text:
            needle = text.strip().lower()
            alias_match = select(NodeAlias.node_id).where(
                NodeAlias.tenant_id == self.tenant_id, NodeAlias.value == needle
            )
            conditions.append(
                or_(Node.name_norm.like(f"%{_like_escape(needle)}%", escape="\\"), Node.id.in_(alias_match))
            )
        if where:
            conditions.extend(PropertyFilter(self.dialect, list_properties).build(Node.properties, where))
        total = self.session.execute(select(func.count()).select_from(Node).where(*conditions)).scalar_one()
        rows = self.session.execute(
            select(Node).where(*conditions).order_by(Node.type, Node.name_norm, Node.id).limit(limit).offset(offset)
        ).scalars()
        return [node_record(r) for r in rows], int(total)

    def iter_nodes(
        self,
        types: Sequence[str],
        *,
        as_of: datetime | None = None,
        where: Mapping[str, Any] | None = None,
        batch: int = 5000,
    ) -> Iterator[NodeRecord]:
        """Stream every node of the given types (keyset pagination; constant memory).

        ``where`` is pushed down to SQL for current-state reads. For ``as_of`` reads it is
        ignored (the historical state may differ from the current row) and the caller filters.
        """
        if not types:
            return
        extra = PropertyFilter(self.dialect).build(Node.properties, where) if where and as_of is None else []
        last = ""
        while True:
            rows = list(
                self.session.execute(
                    select(Node)
                    .where(Node.tenant_id == self.tenant_id, Node.type.in_(list(types)), Node.id > last, *extra)
                    .order_by(Node.id)
                    .limit(batch)
                ).scalars()
            )
            if not rows:
                return
            last = rows[-1].id
            historical: list[str] = []
            for row in rows:
                if as_of is None:
                    if row.deleted_at is None:
                        yield node_record(row)
                elif row.created_at > as_of:
                    continue
                elif row.valid_from <= as_of:
                    if row.deleted_at is None:
                        yield node_record(row)
                else:
                    historical.append(row.id)
            if historical and as_of is not None:
                yield from self._versions_at(historical, as_of, False).values()
            for row in rows:  # keep memory flat while streaming large graphs
                self.session.expunge(row)

    def node_history(self, node_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """Every version of a node, newest first."""
        current = self.session.execute(
            select(Node).where(Node.tenant_id == self.tenant_id, Node.id == node_id)
        ).scalar_one_or_none()
        if current is None:
            return []
        history: list[dict[str, Any]] = [
            {
                "version": current.version,
                "valid_from": current.valid_from,
                "valid_to": None,
                "name": current.name,
                "properties": dict(current.properties or {}),
                "stub": current.stub,
                "deleted": current.deleted_at is not None,
                "changed_by": current.changed_by,
            }
        ]
        versions = self.session.execute(
            select(NodeVersion)
            .where(NodeVersion.tenant_id == self.tenant_id, NodeVersion.node_id == node_id)
            .order_by(NodeVersion.version.desc())
            .limit(limit)
        ).scalars()
        for v in versions:
            history.append(
                {
                    "version": v.version,
                    "valid_from": v.valid_from,
                    "valid_to": v.valid_to,
                    "name": v.name,
                    "properties": dict(v.properties or {}),
                    "stub": v.stub,
                    "deleted": v.deleted,
                    "changed_by": v.changed_by,
                }
            )
        return history

    def count_nodes_by_type(self) -> dict[str, int]:
        rows = self.session.execute(
            select(Node.type, func.count())
            .where(Node.tenant_id == self.tenant_id, Node.deleted_at.is_(None))
            .group_by(Node.type)
        )
        return {t: int(c) for t, c in rows}

    # ------------------------------------------------------------------ #
    # Edges
    # ------------------------------------------------------------------ #
    def _edge_time(self, as_of: datetime | None) -> ColumnElement[bool]:
        if as_of is None:
            return Edge.valid_to.is_(None)
        return and_(Edge.valid_from <= as_of, or_(Edge.valid_to.is_(None), Edge.valid_to > as_of))

    def edges_of(
        self,
        node_ids: Sequence[str],
        *,
        direction: str = "both",
        types: Sequence[str] | None = None,
        as_of: datetime | None = None,
        limit: int | None = None,
        where: Mapping[str, Any] | None = None,
    ) -> tuple[list[EdgeRecord], bool]:
        """Edges touching any of ``node_ids``. Returns ``(edges, truncated)``."""
        if direction not in ("out", "in", "both"):
            raise ValidationFailed("direction must be out, in or both")
        if types is not None and not types:
            return [], False
        ids = list(dict.fromkeys(node_ids))
        out: dict[str, EdgeRecord] = {}
        truncated = False
        extra = PropertyFilter(self.dialect).build(Edge.properties, where) if where else []
        for chunk in chunked(ids, 400):
            sides: list[ColumnElement[bool]] = []
            if direction in ("out", "both"):
                sides.append(Edge.src_id.in_(chunk))
            if direction in ("in", "both"):
                sides.append(Edge.dst_id.in_(chunk))
            stmt = select(Edge).where(Edge.tenant_id == self.tenant_id, or_(*sides), self._edge_time(as_of), *extra)
            if types is not None:
                stmt = stmt.where(Edge.type.in_(list(types)))
            if limit is not None:  # most recently observed first, so truncation keeps the freshest
                stmt = stmt.order_by(Edge.last_seen.desc(), Edge.id).limit(limit - len(out) + 1)
            for row in self.session.execute(stmt).scalars():
                if limit is not None and len(out) >= limit:
                    truncated = True
                    break
                out[row.id] = edge_record(row)
            if truncated:
                break
        return list(out.values()), truncated

    def edge_counts(self, node_id: str) -> dict[str, dict[str, int]]:
        """Degree by edge type and direction — cheap even for super-nodes."""
        counts: dict[str, dict[str, int]] = {}
        for side, label in ((Edge.src_id, "out"), (Edge.dst_id, "in")):
            rows = self.session.execute(
                select(Edge.type, func.count())
                .where(Edge.tenant_id == self.tenant_id, side == node_id, Edge.valid_to.is_(None))
                .group_by(Edge.type)
            )
            for edge_type, count in rows:
                counts.setdefault(edge_type, {"out": 0, "in": 0})[label] = int(count)
        return counts

    def get_edge(self, lineage_id: str) -> EdgeRecord | None:
        row = self.session.execute(
            select(Edge)
            .where(Edge.tenant_id == self.tenant_id, Edge.lineage_id == lineage_id)
            .order_by(Edge.version.desc())
            .limit(1)
        ).scalar_one_or_none()
        return edge_record(row) if row else None

    def edge_history(self, lineage_id: str) -> list[EdgeRecord]:
        rows = self.session.execute(
            select(Edge)
            .where(Edge.tenant_id == self.tenant_id, Edge.lineage_id == lineage_id)
            .order_by(Edge.version.desc())
        ).scalars()
        return [edge_record(r) for r in rows]

    def iter_edges(
        self, types: Sequence[str], *, as_of: datetime | None = None, batch: int = 10000
    ) -> Iterator[tuple[str, str, str, str, dict[str, Any]]]:
        """Stream ``(lineage_id, type, src, dst, properties)`` for the given edge types."""
        if not types:
            return
        last = ""
        while True:
            rows = self.session.execute(
                select(Edge.id, Edge.lineage_id, Edge.type, Edge.src_id, Edge.dst_id, Edge.properties)
                .where(
                    Edge.tenant_id == self.tenant_id,
                    Edge.type.in_(list(types)),
                    self._edge_time(as_of),
                    Edge.id > last,
                )
                .order_by(Edge.id)
                .limit(batch)
            ).all()
            if not rows:
                return
            last = rows[-1][0]
            for _id, lineage, edge_type, src, dst, props in rows:
                yield lineage, edge_type, src, dst, props or {}

    def count_edges_by_type(self) -> dict[str, int]:
        rows = self.session.execute(
            select(Edge.type, func.count())
            .where(Edge.tenant_id == self.tenant_id, Edge.valid_to.is_(None))
            .group_by(Edge.type)
        )
        return {t: int(c) for t, c in rows}

    def count_edges(self, types: Sequence[str] | None = None) -> int:
        stmt = select(func.count()).select_from(Edge).where(Edge.tenant_id == self.tenant_id, Edge.valid_to.is_(None))
        if types is not None:
            stmt = stmt.where(Edge.type.in_(list(types)) if types else ~true())
        return int(self.session.execute(stmt).scalar_one())

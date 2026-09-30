"""Declarative source mappings.

A mapping is a YAML file that says how one source format becomes canonical
node and edge records. Adding a source is a mapping file plus a fixture, not
code. Mappings are validated against the ontology when they are loaded, so a
mapping that names an unknown type, identifier or property fails at start-up
rather than on the first record.

Value expressions
-----------------
``"$.a.b[0].c"``       path into the current record (``[*]`` fans out, ``[?k=v]`` filters a list)
``"$^.a"``             path into the enclosing record (inside ``foreach``)
``"$$.a"``             path into the document root
``"@name"``            a parameter supplied with the ingest call
anything else          a literal

or an object with exactly one operator::

    {path: "$.x", default: 0, map: {High: high}, transform: lower}
    {concat: ["scan:", "$.host", ":", "$.cve"]}
    {coalesce: ["$.fqdn", "$.hostname"]}
    {literal: "$.not-a-path"}

Conditions (``when``): an expression (true when it yields a non-empty value) or
``{eq: [a, b]}``, ``{ne: [a, b]}``, ``{in: [a, [..]]}``, ``{startswith: [a, "x"]}``,
``{exists: a}``, ``{not: cond}``, ``{all: [..]}``, ``{any: [..]}``.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from secgraph.errors import ConfigurationError, NotFound, ValidationFailed
from secgraph.ingest.canonical import SOURCE_RE, IngestRequest
from secgraph.ontology.model import Ontology

_SEGMENT_RE = re.compile(r"\.([A-Za-z_][\w-]*)|\[(\d+)\]|\[(\*)\]|\[\?([\w.-]+)=([^\]]*)\]")
_TRANSFORMS = {
    "lower",
    "upper",
    "strip",
    "bool",
    "int",
    "float",
    "first",
    "last",
    "unique",
    "string",
    "basename",
    "split_comma",
    "split_semicolon",
    "split_space",
    "percent_to_fraction",
}
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,47}$")
_MISSING = object()


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def compile_path(path: str) -> list[tuple[str, Any]]:
    segments: list[tuple[str, Any]] = []
    position = 0
    while position < len(path):
        match = _SEGMENT_RE.match(path, position)
        if match is None:
            raise ValueError(f"cannot parse path at '{path[position:]}'")
        key, index, wildcard, filter_key, filter_value = match.groups()
        if key is not None:
            segments.append(("key", key))
        elif index is not None:
            segments.append(("index", int(index)))
        elif wildcard is not None:
            segments.append(("all", None))
        else:
            segments.append(("filter", (filter_key, filter_value)))
        position = match.end()
    return segments


def walk(value: Any, segments: list[tuple[str, Any]]) -> Any:
    """Follow a compiled path. Missing anything yields ``None``; ``[*]`` and filters yield lists."""
    current: Any = value
    fanned = False
    for kind, argument in segments:
        if current is None:
            return None
        if fanned:
            items = []
            for item in current:
                result = walk(item, [(kind, argument)])
                if result is None:
                    continue
                if kind in ("all", "filter") and isinstance(result, list):
                    items.extend(result)
                else:
                    items.append(result)
            current = items
            continue
        if kind == "key":
            current = current.get(argument) if isinstance(current, dict) else None
        elif kind == "index":
            current = current[argument] if isinstance(current, list) and len(current) > argument else None
        elif kind == "all":
            if not isinstance(current, list):
                return None
            fanned = True
        else:
            if not isinstance(current, list):
                return None
            key, expected = argument
            current = [item for item in current if isinstance(item, dict) and str(_dig(item, key)) == expected]
            fanned = True
    return current


def _dig(item: dict[str, Any], dotted: str) -> Any:
    current: Any = item
    for part in dotted.split("."):
        current = current.get(part) if isinstance(current, dict) else None
    return current


# --------------------------------------------------------------------------- #
# Expressions
# --------------------------------------------------------------------------- #
@dataclass
class Scope:
    record: Any
    root: Any
    params: dict[str, str]
    parent: Scope | None = None


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _transform(name: str, value: Any) -> Any:
    if value is None:
        return None
    if name == "lower":
        return [str(v).lower() for v in value] if isinstance(value, list) else str(value).lower()
    if name == "upper":
        return [str(v).upper() for v in value] if isinstance(value, list) else str(value).upper()
    if name == "strip":
        return str(value).strip()
    if name == "string":
        return str(value)
    if name == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "yes", "y", "1", "known"}:
            return True
        if text in {"false", "no", "n", "0", "unknown", ""}:
            return False
        return None
    if name in ("int", "float"):
        try:
            number = float(str(value).strip())
        except ValueError:
            return None
        return int(number) if name == "int" else number
    if name == "percent_to_fraction":
        try:
            return float(str(value).strip().rstrip("%")) / 100.0
        except ValueError:
            return None
    if name == "first":
        return (value[0] if value else None) if isinstance(value, list) else value
    if name == "last":
        return (value[-1] if value else None) if isinstance(value, list) else value
    if name == "unique":
        return list(dict.fromkeys(value)) if isinstance(value, list) else value
    if name == "basename":
        return str(value).rsplit("/", 1)[-1]
    separators = {"split_comma": ",", "split_semicolon": ";", "split_space": None}
    if name in separators:
        if isinstance(value, list):
            return value
        parts = str(value).split(separators[name])
        return [p.strip() for p in parts if p.strip()]
    raise ValueError(f"unknown transform '{name}'")  # pragma: no cover - validated at load


class Expression:
    """A compiled value expression."""

    def __init__(self, spec: Any, where: str):
        self.where = where
        self.kind = "literal"
        self.value: Any = spec
        self.path: list[tuple[str, Any]] = []
        self.parts: list[Expression] = []
        self.default: Any = None
        self.map: dict[str, Any] | None = None
        self.transforms: list[str] = []
        if isinstance(spec, str):
            self._from_string(spec)
        elif isinstance(spec, dict):
            self._from_object(spec)
        elif isinstance(spec, list):
            raise ConfigurationError(f"{where}: a list is not a value expression")

    def _from_string(self, spec: str) -> None:
        try:
            if spec.startswith("$$."):
                self.kind, self.path = "root", compile_path(spec[2:])
            elif spec.startswith("$^."):
                self.kind, self.path = "parent", compile_path(spec[2:])
            elif spec.startswith("$."):
                self.kind, self.path = "record", compile_path(spec[1:])
            elif spec == "$":
                self.kind = "record"
            elif spec.startswith("@") and len(spec) > 1:
                self.kind, self.value = "param", spec[1:]
        except ValueError as exc:
            raise ConfigurationError(f"{self.where}: {exc}") from exc

    def _from_object(self, spec: dict[str, Any]) -> None:
        operators = {"path", "concat", "coalesce", "literal"} & set(spec)
        if len(operators) != 1:
            raise ConfigurationError(f"{self.where}: expected exactly one of path, concat, coalesce, literal")
        unknown = set(spec) - {"path", "concat", "coalesce", "literal", "default", "map", "transform"}
        if unknown:
            raise ConfigurationError(f"{self.where}: unknown key(s) {', '.join(sorted(unknown))}")
        operator = operators.pop()
        if operator == "literal":
            self.kind, self.value = "literal", spec["literal"]
        elif operator == "path":
            inner = Expression(spec["path"], self.where)
            if inner.kind == "literal":
                raise ConfigurationError(f"{self.where}: 'path' must start with $., $^., $$. or @")
            self.kind, self.path, self.value = inner.kind, inner.path, inner.value
        else:
            items = spec[operator]
            if not isinstance(items, list) or not items:
                raise ConfigurationError(f"{self.where}: '{operator}' needs a non-empty list")
            self.kind = operator
            self.parts = [Expression(item, f"{self.where}.{operator}[{i}]") for i, item in enumerate(items)]
        self.default = spec.get("default")
        mapping = spec.get("map")
        if mapping is not None:
            if not isinstance(mapping, dict):
                raise ConfigurationError(f"{self.where}: 'map' must be an object")
            self.map = {str(k).lower(): v for k, v in mapping.items()}
        transforms = spec.get("transform", [])
        transforms = [transforms] if isinstance(transforms, str) else transforms
        for name in transforms:
            if name not in _TRANSFORMS:
                raise ConfigurationError(f"{self.where}: unknown transform '{name}'")
        self.transforms = list(transforms)

    def evaluate(self, scope: Scope) -> Any:
        if self.kind == "literal":
            value = self.value
        elif self.kind == "record":
            value = walk(scope.record, self.path)
        elif self.kind == "parent":
            value = walk(scope.parent.record, self.path) if scope.parent else None
        elif self.kind == "root":
            value = walk(scope.root, self.path)
        elif self.kind == "param":
            value = scope.params.get(self.value)
        elif self.kind == "coalesce":
            value = None
            for part in self.parts:
                candidate = part.evaluate(scope)
                if not _empty(candidate):
                    value = candidate
                    break
        else:  # concat
            pieces: list[str] = []
            for part in self.parts:
                piece = part.evaluate(scope)
                if _empty(piece):
                    pieces = []
                    break
                pieces.append(str(piece))
            value = "".join(pieces) if pieces else None
        if isinstance(value, str):
            value = value.strip()
        if self.map is not None and not _empty(value) and not isinstance(value, list | dict):
            value = self.map.get(str(value).lower(), self.map.get("*", value))
        for name in self.transforms:
            value = _transform(name, value)
        if _empty(value):
            value = self.default
        return value


class Condition:
    def __init__(self, spec: Any, where: str):
        self.where = where
        self.operator = "truthy"
        self.items: list[Any] = []
        if (
            isinstance(spec, dict)
            and len(spec) == 1
            and next(iter(spec)) in {"eq", "ne", "in", "startswith", "exists", "not", "all", "any"}
        ):
            self.operator, argument = next(iter(spec.items()))
            if self.operator in ("all", "any"):
                if not isinstance(argument, list) or not argument:
                    raise ConfigurationError(f"{where}: '{self.operator}' needs a non-empty list")
                self.items = [Condition(item, f"{where}.{self.operator}[{i}]") for i, item in enumerate(argument)]
            elif self.operator == "not":
                self.items = [Condition(argument, f"{where}.not")]
            elif self.operator == "exists":
                self.items = [Expression(argument, where)]
            else:
                if not isinstance(argument, list) or len(argument) != 2:
                    raise ConfigurationError(f"{where}: '{self.operator}' needs [value, expected]")
                right: Any = argument[1] if self.operator == "in" else Expression(argument[1], where)
                if self.operator == "in" and not isinstance(right, list):
                    raise ConfigurationError(f"{where}: 'in' needs a list of allowed values")
                self.items = [Expression(argument[0], where), right]
        else:
            self.items = [Expression(spec, where)]

    def test(self, scope: Scope) -> bool:
        op = self.operator
        if op == "truthy":
            value = self.items[0].evaluate(scope)
            return not _empty(value) and value is not False
        if op == "exists":
            return not _empty(self.items[0].evaluate(scope))
        if op == "not":
            return not self.items[0].test(scope)
        if op == "all":
            return all(item.test(scope) for item in self.items)
        if op == "any":
            return any(item.test(scope) for item in self.items)
        left = self.items[0].evaluate(scope)
        if op == "in":
            return left in self.items[1]
        right = self.items[1].evaluate(scope)
        if op == "eq":
            return bool(left == right)
        if op == "ne":
            return bool(left != right)
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)


# --------------------------------------------------------------------------- #
# Mapping definition
# --------------------------------------------------------------------------- #
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MappingMeta(_Strict):
    name: str
    version: int = 1
    description: str = ""
    format: Literal["json", "jsonl", "csv"] = "json"
    source: str
    records: str = "$"
    parameters: dict[str, str] = Field(default_factory=dict)  # name -> description
    required_parameters: list[str] = Field(default_factory=list)


class NodeSpec(_Strict):
    type: str
    ref: str | None = None
    identifiers: dict[str, Any]
    properties: dict[str, Any] = Field(default_factory=dict)
    name: Any | None = None
    observed_at: Any | None = None
    confidence: Any | None = None
    when: Any | None = None
    optional: bool = False


class EndpointSpec(_Strict):
    ref: str | None = None
    type: str | None = None
    identifiers: dict[str, Any] | None = None


class EdgeSpec(_Strict):
    type: str
    source: EndpointSpec
    target: EndpointSpec
    key: Any | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    observed_at: Any | None = None
    when: Any | None = None


class EmitSpec(_Strict):
    node: NodeSpec | None = None
    edge: EdgeSpec | None = None
    foreach: Any | None = None
    when: Any | None = None
    emit: list[EmitSpec] | None = None


class MappingFile(_Strict):
    mapping: MappingMeta
    emit: list[EmitSpec]


@dataclass
class _CompiledNode:
    spec: NodeSpec
    identifiers: dict[str, Expression]
    properties: dict[str, Expression]
    name: Expression | None
    observed_at: Expression | None
    confidence: Expression | None
    when: Condition | None


@dataclass
class _CompiledEndpoint:
    ref: str | None
    type: str | None
    identifiers: dict[str, Expression]


@dataclass
class _CompiledEdge:
    spec: EdgeSpec
    source: _CompiledEndpoint
    target: _CompiledEndpoint
    key: Expression | None
    properties: dict[str, Expression]
    observed_at: Expression | None
    when: Condition | None


@dataclass
class _CompiledEmit:
    node: _CompiledNode | None = None
    edge: _CompiledEdge | None = None
    foreach: Expression | None = None
    when: Condition | None = None
    children: list[_CompiledEmit] = field(default_factory=list)


@dataclass
class MappedBatch:
    request: IngestRequest
    source_records: int
    errors: list[tuple[int, Any, str]]  # (record index, record, reason)


class Mapping:
    def __init__(self, document: Any, ontology: Ontology, origin: str):
        self.origin = origin
        try:
            self.definition = MappingFile.model_validate(document)
        except ValidationError as exc:
            errors = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:8])
            raise ConfigurationError(f"{origin}: invalid mapping: {errors}") from exc
        meta = self.definition.mapping
        if not _NAME_RE.match(meta.name):
            raise ConfigurationError(f"{origin}: mapping names are snake_case, 2-48 characters")
        if not SOURCE_RE.match(meta.source):
            raise ConfigurationError(f"{origin}: invalid default source '{meta.source}'")
        self.name = meta.name
        self.meta = meta
        self.ontology = ontology
        try:
            records = Expression(meta.records, f"{origin}: mapping.records")
        except ConfigurationError:
            raise
        if records.kind not in ("record", "literal") or (records.kind == "literal" and meta.records != "$"):
            raise ConfigurationError(f"{origin}: mapping.records must be a path starting with '$'")
        self._records_path = records.path
        refs: set[str] = set()
        self._emit = [self._compile(spec, f"{origin}: emit[{i}]", refs) for i, spec in enumerate(self.definition.emit)]

    # -- compilation ------------------------------------------------------- #
    def _expressions(self, values: dict[str, Any], where: str) -> dict[str, Expression]:
        return {key: Expression(spec, f"{where}.{key}") for key, spec in values.items()}

    def _compile(self, spec: EmitSpec, where: str, refs: set[str]) -> _CompiledEmit:
        chosen = [x for x in (spec.node, spec.edge, spec.emit) if x is not None]
        if len(chosen) != 1:
            raise ConfigurationError(f"{where}: give exactly one of 'node', 'edge' or a nested 'emit'")
        if spec.emit is not None and spec.foreach is None:
            raise ConfigurationError(f"{where}: a nested 'emit' needs 'foreach'")
        compiled = _CompiledEmit(when=Condition(spec.when, f"{where}.when") if spec.when is not None else None)
        if spec.foreach is not None:
            expression = Expression(spec.foreach, f"{where}.foreach")
            if expression.kind == "literal":
                raise ConfigurationError(f"{where}.foreach must be a path or an expression that yields a list")
            compiled.foreach = expression
        if spec.node is not None:
            compiled.node = self._compile_node(spec.node, f"{where}.node")
            if spec.node.ref:
                refs.add(spec.node.ref)
        elif spec.edge is not None:
            compiled.edge = self._compile_edge(spec.edge, f"{where}.edge", refs)
        else:
            assert spec.emit is not None
            inner = set(refs)
            compiled.children = [self._compile(child, f"{where}.emit[{i}]", inner) for i, child in enumerate(spec.emit)]
        return compiled

    def _compile_node(self, spec: NodeSpec, where: str) -> _CompiledNode:
        node_type = self.ontology.node_type(spec.type)
        if node_type is None:
            raise ConfigurationError(f"{where}: unknown node type '{spec.type}'")
        if not spec.identifiers:
            raise ConfigurationError(f"{where}: at least one identifier is required")
        for kind in spec.identifiers:
            if node_type.identifier(kind) is None:
                raise ConfigurationError(f"{where}: {spec.type} has no identifier '{kind}'")
        if not node_type.additional_properties:
            for prop in spec.properties:
                if prop not in node_type.properties:
                    raise ConfigurationError(f"{where}: {spec.type} has no property '{prop}'")
        return _CompiledNode(
            spec=spec,
            identifiers=self._expressions(spec.identifiers, f"{where}.identifiers"),
            properties=self._expressions(spec.properties, f"{where}.properties"),
            name=Expression(spec.name, f"{where}.name") if spec.name is not None else None,
            observed_at=Expression(spec.observed_at, f"{where}.observed_at") if spec.observed_at is not None else None,
            confidence=Expression(spec.confidence, f"{where}.confidence") if spec.confidence is not None else None,
            when=Condition(spec.when, f"{where}.when") if spec.when is not None else None,
        )

    def _compile_endpoint(self, spec: EndpointSpec, where: str, refs: set[str]) -> _CompiledEndpoint:
        if (spec.ref is None) == (spec.type is None):
            raise ConfigurationError(f"{where}: give either 'ref' or 'type' + 'identifiers'")
        if spec.ref is not None:
            if spec.ref not in refs:
                raise ConfigurationError(f"{where}: ref '{spec.ref}' is not defined by an earlier node")
            return _CompiledEndpoint(ref=spec.ref, type=None, identifiers={})
        node_type = self.ontology.node_type(spec.type or "")
        if node_type is None:
            raise ConfigurationError(f"{where}: unknown node type '{spec.type}'")
        if not spec.identifiers:
            raise ConfigurationError(f"{where}: 'identifiers' is required with 'type'")
        for kind in spec.identifiers:
            if node_type.identifier(kind) is None:
                raise ConfigurationError(f"{where}: {spec.type} has no identifier '{kind}'")
        return _CompiledEndpoint(
            ref=None, type=spec.type, identifiers=self._expressions(spec.identifiers, f"{where}.identifiers")
        )

    def _compile_edge(self, spec: EdgeSpec, where: str, refs: set[str]) -> _CompiledEdge:
        edge_type = self.ontology.edge_type(spec.type)
        if edge_type is None:
            raise ConfigurationError(f"{where}: unknown edge type '{spec.type}'")
        for side, endpoint, allowed in (
            ("source", spec.source, edge_type.source),
            ("target", spec.target, edge_type.target),
        ):
            if endpoint.type is not None and endpoint.type not in allowed:
                raise ConfigurationError(
                    f"{where}.{side}: {spec.type} does not allow {endpoint.type} here (allowed: {', '.join(allowed)})"
                )
        if not edge_type.additional_properties:
            for prop in spec.properties:
                if prop not in edge_type.properties:
                    raise ConfigurationError(f"{where}: {spec.type} has no property '{prop}'")
        return _CompiledEdge(
            spec=spec,
            source=self._compile_endpoint(spec.source, f"{where}.source", refs),
            target=self._compile_endpoint(spec.target, f"{where}.target", refs),
            key=Expression(spec.key, f"{where}.key") if spec.key is not None else None,
            properties=self._expressions(spec.properties, f"{where}.properties"),
            observed_at=Expression(spec.observed_at, f"{where}.observed_at") if spec.observed_at is not None else None,
            when=Condition(spec.when, f"{where}.when") if spec.when is not None else None,
        )

    # -- parsing ----------------------------------------------------------- #
    def parse(self, payload: bytes | str | Any) -> tuple[Any, list[Any]]:
        """Return ``(document root, records)`` for a raw payload in this mapping's format."""
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValidationFailed("payload is not valid UTF-8") from exc
        fmt = self.meta.format
        if fmt == "csv":
            if not isinstance(payload, str):
                raise ValidationFailed(f"mapping '{self.name}' expects CSV text")
            lines = [line for line in payload.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            reader = csv.DictReader(io.StringIO("\n".join(lines)))
            if not reader.fieldnames:
                raise ValidationFailed("CSV payload has no header row")
            rows = [
                {(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()} for row in reader
            ]
            return rows, rows
        if fmt == "jsonl":
            if not isinstance(payload, str):
                raise ValidationFailed(f"mapping '{self.name}' expects JSON Lines text")
            records = []
            for number, line in enumerate(payload.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValidationFailed(f"line {number} is not valid JSON: {exc.msg}") from exc
            return records, records
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValidationFailed(f"payload is not valid JSON: {exc.msg} at position {exc.pos}") from exc
        records = walk(payload, self._records_path) if self._records_path else payload
        if records is None:
            records = []
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            raise ValidationFailed(f"'{self.meta.records}' did not select a list of records")
        return payload, records

    # -- evaluation -------------------------------------------------------- #
    def _values(self, expressions: dict[str, Expression], scope: Scope) -> dict[str, Any]:
        out = {}
        for key, expression in expressions.items():
            value = expression.evaluate(scope)
            if not _empty(value):
                out[key] = value
        return out

    def _run(
        self,
        items: list[_CompiledEmit],
        scope: Scope,
        prefix: str,
        refs: dict[str, str | None],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        for position, item in enumerate(items):
            if item.when is not None and not item.when.test(scope):
                continue
            if item.foreach is not None:
                values = item.foreach.evaluate(scope)
                if values is None:
                    continue
                if not isinstance(values, list):
                    values = [values]
                for index, value in enumerate(values):
                    inner = Scope(record=value, root=scope.root, params=scope.params, parent=scope)
                    inner_refs = dict(refs)
                    inner_prefix = f"{prefix}.{position}.{index}"
                    if item.children:
                        self._run(item.children, inner, inner_prefix, inner_refs, nodes, edges)
                    else:
                        self._emit_one(item, inner, inner_prefix, inner_refs, nodes, edges)
                continue
            self._emit_one(item, scope, prefix, refs, nodes, edges)

    def _emit_one(
        self,
        item: _CompiledEmit,
        scope: Scope,
        prefix: str,
        refs: dict[str, str | None],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        if item.node is not None:
            node = item.node
            if node.when is not None and not node.when.test(scope):
                if node.spec.ref:
                    refs[node.spec.ref] = None
                return
            identifiers = self._values(node.identifiers, scope)
            if not identifiers and node.spec.optional:
                if node.spec.ref:
                    refs[node.spec.ref] = None
                return
            record: dict[str, Any] = {
                "type": node.spec.type,
                "identifiers": identifiers,
                "properties": self._values(node.properties, scope),
            }
            if node.spec.ref:
                record["ref"] = f"{prefix}:{node.spec.ref}"
                refs[node.spec.ref] = record["ref"]
            for key, expression in (
                ("name", node.name),
                ("observed_at", node.observed_at),
                ("confidence", node.confidence),
            ):
                if expression is not None:
                    value = expression.evaluate(scope)
                    if not _empty(value):
                        record[key] = str(value) if key == "name" else value
            nodes.append(record)
            return
        assert item.edge is not None
        edge = item.edge
        if edge.when is not None and not edge.when.test(scope):
            return
        endpoints: dict[str, dict[str, Any]] = {}
        for side, endpoint in (("source", edge.source), ("target", edge.target)):
            if endpoint.ref is not None:
                ref = refs.get(endpoint.ref)
                if ref is None:
                    return  # the node this edge hangs on was not emitted for this record
                endpoints[side] = {"ref": ref}
            else:
                identifiers = self._values(endpoint.identifiers, scope)
                if not identifiers:
                    return
                endpoints[side] = {"type": endpoint.type, "identifiers": identifiers}
        record = {
            "type": edge.spec.type,
            "source": endpoints["source"],
            "target": endpoints["target"],
            "properties": self._values(edge.properties, scope),
        }
        if edge.key is not None:
            key = edge.key.evaluate(scope)
            if not _empty(key):
                record["key"] = str(key)[:128]
        if edge.observed_at is not None:
            observed = edge.observed_at.evaluate(scope)
            if not _empty(observed):
                record["observed_at"] = observed
        edges.append(record)

    def apply(
        self,
        payload: bytes | str | Any,
        params: dict[str, str] | None = None,
        *,
        source: str | None = None,
        max_records: int = 5000,
    ) -> Iterator[MappedBatch]:
        """Yield canonical batches. Source records are never split across batches."""
        params = dict(params or {})
        missing = [p for p in self.meta.required_parameters if not params.get(p)]
        if missing:
            raise ValidationFailed(f"mapping '{self.name}' needs parameter(s): {', '.join(missing)}")
        unknown = set(params) - set(self.meta.parameters) - set(self.meta.required_parameters)
        if unknown:
            raise ValidationFailed(f"mapping '{self.name}' does not take parameter(s): {', '.join(sorted(unknown))}")
        root, records = self.parse(payload)
        name = source or self.meta.source
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        errors: list[tuple[int, Any, str]] = []
        count = 0
        for index, record in enumerate(records):
            record_nodes: list[dict[str, Any]] = []
            record_edges: list[dict[str, Any]] = []
            try:
                self._run(
                    self._emit,
                    Scope(record=record, root=root, params=params),
                    f"r{index}",
                    {},
                    record_nodes,
                    record_edges,
                )
            except Exception as exc:  # a malformed record must not stop the file
                errors.append((index, record, f"mapping '{self.name}' failed on this record: {exc}"))
                continue
            if nodes and len(nodes) + len(edges) + len(record_nodes) + len(record_edges) > max_records:
                yield MappedBatch(IngestRequest(source=name, nodes=nodes, edges=edges), count, errors)
                nodes, edges, errors, count = [], [], [], 0
            nodes.extend(record_nodes)
            edges.extend(record_edges)
            count += 1
        if nodes or edges or errors or count:
            yield MappedBatch(IngestRequest(source=name, nodes=nodes, edges=edges), count, errors)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.meta.version,
            "description": self.meta.description,
            "format": self.meta.format,
            "source": self.meta.source,
            "parameters": self.meta.parameters,
            "required_parameters": self.meta.required_parameters,
            "content_type": "text/csv" if self.meta.format == "csv" else "application/json",
        }


class MappingRegistry:
    """Packaged mappings plus any in ``directory`` (which may override a packaged one by name)."""

    def __init__(self, ontology: Ontology, directory: str | None = None):
        self.ontology = ontology
        self._mappings: dict[str, Mapping] = {}
        package = resources.files("secgraph.ingest").joinpath("mappings")
        for entry in sorted(package.iterdir(), key=lambda e: e.name):
            if entry.name.endswith((".yaml", ".yml")):
                self._load(entry.read_text(encoding="utf-8"), f"secgraph/ingest/mappings/{entry.name}")
        if directory:
            folder = Path(directory)
            if not folder.is_dir():
                raise ConfigurationError(f"mappings directory not found: {directory}")
            for file in sorted(folder.glob("*.y*ml")):
                self._load(file.read_text(encoding="utf-8"), str(file))

    def _load(self, text: str, origin: str) -> None:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"{origin}: not valid YAML: {exc}") from exc
        mapping = Mapping(document, self.ontology, origin)
        self._mappings[mapping.name] = mapping

    def get(self, name: str) -> Mapping:
        mapping = self._mappings.get(name)
        if mapping is None:
            raise NotFound(f"unknown mapping '{name}'; available: {', '.join(sorted(self._mappings))}")
        return mapping

    def names(self) -> list[str]:
        return sorted(self._mappings)

    def describe(self) -> list[dict[str, Any]]:
        return [self._mappings[name].describe() for name in self.names()]

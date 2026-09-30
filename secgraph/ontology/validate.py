"""Record validation and coercion against the ontology.

Sources are messy: numbers arrive as strings, booleans as ``"yes"``, timestamps
in four formats. Values are coerced when the intent is unambiguous and
rejected — with a precise reason — when it is not. A rejected record is
quarantined by the ingest layer, never silently dropped.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from datetime import UTC, date, datetime
from typing import Any

from secgraph.errors import ValidationFailed
from secgraph.ontology.model import EdgeTypeDef, NodeTypeDef, PropertyDef
from secgraph.ontology.normalize import derive_identifier, normalize_identifier

_TRUE = {"true", "yes", "y", "1", "on"}
_FALSE = {"false", "no", "n", "0", "off"}
_PROP_NAME_MAX = 64
_STRING_DEFAULT_MAX = 4000
_LIST_MAX_ITEMS = 200


def parse_datetime(value: Any) -> datetime:
    """Parse the timestamp shapes real sources produce into an aware UTC datetime."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    elif isinstance(value, int | float):
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError("timestamp out of range")
        if number > 1e11:  # epoch milliseconds
            number /= 1000.0
        dt = datetime.fromtimestamp(number, UTC)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
                try:
                    dt = datetime.strptime(text, fmt)  # noqa: DTZ007 - made aware below
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(f"unrecognised timestamp {value!r}") from None
    else:
        raise ValueError(f"cannot read a timestamp from {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def format_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce(name: str, definition: PropertyDef, value: Any) -> Any:
    kind = definition.type
    if kind == "string":
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            raise ValueError("expected a string")
        text = str(value)
        limit = definition.max_length or _STRING_DEFAULT_MAX
        if len(text) > limit:
            raise ValueError(f"longer than {limit} characters")
        return text
    if kind == "enum":
        if not isinstance(value, str):
            raise ValueError("expected one of " + ", ".join(definition.values or ()))
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text not in (definition.values or ()):
            raise ValueError(f"{value!r} is not one of " + ", ".join(definition.values or ()))
        return text
    if kind == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
            return value.strip().lower() in _TRUE
        raise ValueError("expected true or false")
    if kind in ("integer", "number"):
        if isinstance(value, bool):
            raise ValueError("expected a number")
        if isinstance(value, str):
            try:
                value = float(value.strip())
            except ValueError:
                raise ValueError("expected a number") from None
        if not isinstance(value, int | float) or not math.isfinite(float(value)):
            raise ValueError("expected a finite number")
        if kind == "integer":
            if float(value) != int(value):
                raise ValueError("expected a whole number")
            number: int | float = int(value)
        else:
            number = float(value)
        if definition.minimum is not None and number < definition.minimum:
            raise ValueError(f"below the minimum {definition.minimum:g}")
        if definition.maximum is not None and number > definition.maximum:
            raise ValueError(f"above the maximum {definition.maximum:g}")
        return number
    if kind == "datetime":
        return format_datetime(parse_datetime(value))
    if kind == "string_list":
        if isinstance(value, str):
            items = [part.strip() for part in value.split(",")]
        elif isinstance(value, list | tuple | set):
            items = []
            for item in value:
                if isinstance(item, bool) or not isinstance(item, str | int | float):
                    raise ValueError("expected a list of strings")
                items.append(str(item).strip())
        else:
            raise ValueError("expected a list of strings")
        items = [i for i in dict.fromkeys(items) if i]
        if len(items) > _LIST_MAX_ITEMS:
            raise ValueError(f"more than {_LIST_MAX_ITEMS} items")
        if any(len(i) > 512 for i in items):
            raise ValueError("list item longer than 512 characters")
        return items
    if kind == "json":
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError):
            raise ValueError("expected JSON-serialisable data") from None
        return value
    raise ValueError(f"unknown property type {kind}")  # pragma: no cover - guarded by the schema


def _check_additional(name: str, value: Any) -> Any:
    if len(name) > _PROP_NAME_MAX or not name or not name.replace("_", "a").replace(".", "a").isalnum():
        raise ValueError("property names are letters, digits, '_' or '.' (max 64 characters)")
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError("expected JSON-serialisable data") from None
    return value


def coerce_properties(
    type_name: str,
    definitions: Mapping[str, PropertyDef],
    additional_properties: bool,
    properties: Mapping[str, Any] | None,
    *,
    enforce_required: bool,
    max_bytes: int,
) -> dict[str, Any]:
    """Return cleaned properties. ``None`` values are kept: they mean "remove this property"."""
    problems: list[str] = []
    cleaned: dict[str, Any] = {}
    for name, value in (properties or {}).items():
        if not isinstance(name, str):
            problems.append(f"property name {name!r} is not a string")
            continue
        if value is None:
            cleaned[name] = None
            continue
        definition = definitions.get(name)
        try:
            if definition is not None:
                cleaned[name] = _coerce(name, definition, value)
            elif additional_properties:
                cleaned[name] = _check_additional(name, value)
            else:
                problems.append(f"{type_name}.{name}: not declared in the ontology")
        except ValueError as exc:
            problems.append(f"{type_name}.{name}: {exc}")
    if enforce_required:
        for name, definition in definitions.items():
            if definition.required and cleaned.get(name) is None:
                problems.append(f"{type_name}.{name}: required")
    if not problems:
        size = len(json.dumps(cleaned, separators=(",", ":"), default=str))
        if size > max_bytes:
            problems.append(f"{type_name}: properties are {size} bytes, above the {max_bytes} byte limit")
    if problems:
        raise ValidationFailed("; ".join(problems), detail={"problems": problems})
    return cleaned


def normalize_identifiers(
    type_name: str, definition: NodeTypeDef, identifiers: Mapping[str, Any] | None
) -> list[tuple[str, str]]:
    """Return ``(kind, canonical value)`` pairs in ontology priority order, derived ones included."""
    if not identifiers:
        raise ValidationFailed(f"{type_name}: at least one identifier is required")
    problems: list[str] = []
    by_kind: dict[str, list[str]] = {}
    for kind, raw in identifiers.items():
        ident = definition.identifier(kind) if isinstance(kind, str) else None
        if ident is None:
            known = ", ".join(i.kind for i in definition.identifiers)
            problems.append(f"{type_name}: unknown identifier '{kind}' (known: {known})")
            continue
        if raw is None:
            continue
        values = raw if isinstance(raw, list | tuple | set) else [raw]
        if len(values) > 64:
            problems.append(f"{type_name}.{kind}: more than 64 values")
            continue
        for value in values:
            try:
                canonical = normalize_identifier(ident.normalize, kind, value)
            except ValidationFailed as exc:
                problems.append(exc.message)
                continue
            if canonical not in by_kind.setdefault(kind, []):
                by_kind[kind].append(canonical)
        if ident.exclusive and len(by_kind.get(kind, [])) > 1:
            problems.append(f"{type_name}.{kind}: exclusive identifier given {len(by_kind[kind])} different values")
    if problems:
        raise ValidationFailed("; ".join(problems), detail={"problems": problems})

    for ident in definition.identifiers:
        if ident.derived_from and ident.derive and ident.kind not in by_kind:
            for source_value in by_kind.get(ident.derived_from, []):
                derived = derive_identifier(ident.derive, source_value)
                if derived:
                    try:
                        canonical = normalize_identifier(ident.normalize, ident.kind, derived)
                    except ValidationFailed:
                        continue
                    if canonical not in by_kind.setdefault(ident.kind, []):
                        by_kind[ident.kind].append(canonical)

    ordered = [(i.kind, v) for i in definition.identifiers for v in by_kind.get(i.kind, [])]
    if not ordered:
        raise ValidationFailed(f"{type_name}: at least one identifier is required")
    if not any((d := definition.identifier(k)) and d.match for k, _ in ordered):
        raise ValidationFailed(
            f"{type_name}: none of the identifiers given ({', '.join(sorted(by_kind))}) can identify an entity"
        )
    return ordered


def check_edge_endpoints(edge_type: str, definition: EdgeTypeDef, source_type: str, target_type: str) -> None:
    if source_type not in definition.source:
        raise ValidationFailed(f"{edge_type}: source must be one of {', '.join(definition.source)}, got {source_type}")
    if target_type not in definition.target:
        raise ValidationFailed(f"{edge_type}: target must be one of {', '.join(definition.target)}, got {target_type}")


# --------------------------------------------------------------------------- #
# Predicates (used by attack semantics and pattern queries)
# --------------------------------------------------------------------------- #
_OPS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "exists", "contains"}


def validate_predicate(where: Mapping[str, Any]) -> None:
    for key, condition in where.items():
        if not isinstance(key, str) or not key:
            raise ValidationFailed("predicate keys must be property names")
        if isinstance(condition, Mapping):
            unknown = set(condition) - _OPS
            if unknown:
                raise ValidationFailed(f"unknown predicate operator(s): {', '.join(sorted(unknown))}")
            for op in ("in", "nin"):
                if op in condition and not isinstance(condition[op], list | tuple):
                    raise ValidationFailed(f"'{op}' needs a list")


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        return (actual is not None) == bool(expected)
    if op == "eq":
        return bool(actual == expected)
    if op == "ne":
        return bool(actual != expected)
    if op == "in":
        return actual in expected
    if op == "nin":
        return actual not in expected
    if actual is None:
        return False
    if op == "contains":
        if isinstance(actual, str):
            return str(expected).lower() in actual.lower()
        if isinstance(actual, list):
            return expected in actual
        return False
    try:
        if op == "gt":
            return bool(actual > expected)
        if op == "gte":
            return bool(actual >= expected)
        if op == "lt":
            return bool(actual < expected)
        if op == "lte":
            return bool(actual <= expected)
    except TypeError:
        return False
    return False  # pragma: no cover - operators are validated up front


def matches(properties: Mapping[str, Any], where: Mapping[str, Any]) -> bool:
    """``{"zone": "dmz", "criticality": {"gte": 4}}`` — all conditions must hold."""
    for key, condition in where.items():
        actual = properties.get(key)
        if isinstance(condition, Mapping):
            if not all(_compare(actual, op, expected) for op, expected in condition.items()):
                return False
        elif actual != condition:
            return False
    return True

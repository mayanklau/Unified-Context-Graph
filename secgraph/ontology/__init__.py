"""Ontology loading. ``get_ontology()`` is the process-wide, validated ontology."""

from __future__ import annotations

import threading
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from secgraph.errors import OntologyError
from secgraph.ontology.model import (
    AttackSemantics,
    EdgeTypeDef,
    IdentifierDef,
    NodeTypeDef,
    Ontology,
    PropertyDef,
)
from secgraph.ontology.validate import validate_predicate

PACKAGED_ONTOLOGY = "core.ontology.yaml"

_lock = threading.Lock()
_cache: dict[str, Ontology] = {}


def parse_ontology(document: Any, *, origin: str = "<memory>") -> Ontology:
    if not isinstance(document, dict):
        raise OntologyError(f"{origin}: the ontology must be a YAML mapping")
    try:
        ontology = Ontology.model_validate(document)
    except ValidationError as exc:
        errors = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        raise OntologyError(f"{origin}: invalid ontology", detail={"errors": errors}) from exc
    ontology.check_integrity()
    sem = ontology.attack_semantics
    try:
        for predicate in (
            *(rule.where for rule in sem.entries),
            *(rule.where for rule in sem.transitions),
            *(rule.where for rule in sem.targets),
        ):
            validate_predicate(predicate)
    except Exception as exc:
        raise OntologyError(f"{origin}: invalid predicate in attack semantics: {exc}") from exc
    return ontology


def load_ontology(path: str | Path | None = None) -> Ontology:
    """Load and validate an ontology file; the packaged core ontology when ``path`` is ``None``."""
    if path is None:
        text = resources.files("secgraph.ontology").joinpath(PACKAGED_ONTOLOGY).read_text(encoding="utf-8")
        origin = f"secgraph/ontology/{PACKAGED_ONTOLOGY}"
    else:
        file = Path(path)
        if not file.is_file():
            raise OntologyError(f"ontology file not found: {path}")
        text = file.read_text(encoding="utf-8")
        origin = str(path)
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise OntologyError(f"{origin}: not valid YAML: {exc}") from exc
    return parse_ontology(document, origin=origin)


def get_ontology(path: str | None = None) -> Ontology:
    key = path or ""
    with _lock:
        if key not in _cache:
            _cache[key] = load_ontology(path)
        return _cache[key]


def reset_ontology_cache() -> None:
    with _lock:
        _cache.clear()


__all__ = [
    "AttackSemantics",
    "EdgeTypeDef",
    "IdentifierDef",
    "NodeTypeDef",
    "Ontology",
    "PropertyDef",
    "get_ontology",
    "load_ontology",
    "parse_ontology",
    "reset_ontology_cache",
]

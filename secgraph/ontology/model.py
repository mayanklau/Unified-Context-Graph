"""The ontology as typed data.

The ontology is *data, not code*: node types, edge types, identity rules and
the attack semantics that turn the graph into an attack graph all live in one
versioned YAML file. Changing what the graph means is a reviewed change to
that file, never a code change.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secgraph.errors import OntologyError

_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_EDGE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PROP_RE = re.compile(r"^[a-z][a-z0-9_]*$")

PropertyType = Literal["string", "integer", "number", "boolean", "datetime", "enum", "string_list", "json"]
Normalizer = Literal[
    "none", "lower", "upper", "hostname", "fqdn", "mac", "ip", "cidr", "email", "cve", "attack_id", "purl", "cpe"
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PropertyDef(_Strict):
    type: PropertyType = "string"
    description: str = ""
    required: bool = False
    values: tuple[str, ...] | None = None  # enum members
    minimum: float | None = None
    maximum: float | None = None
    max_length: int | None = None
    sensitive: bool = False  # masked unless the caller holds the ``pii:read`` permission

    @model_validator(mode="after")
    def _check(self) -> PropertyDef:
        if self.type == "enum" and not self.values:
            raise ValueError("enum properties must declare 'values'")
        if self.type != "enum" and self.values is not None:
            raise ValueError("'values' is only valid for enum properties")
        return self


class IdentifierDef(_Strict):
    """One way of recognising an entity of a type (the identity spine).

    * strong (default) — a match on this identifier alone identifies the entity
    * ``weak`` — only consulted when no strong identifier matched, and only
      accepted when exactly one compatible candidate exists
    * ``exclusive`` — an entity has at most one value; two records carrying
      different values are different entities
    * ``match: false`` — stored and searchable, never used to merge records
    """

    kind: str
    description: str = ""
    normalize: Normalizer = "lower"
    weak: bool = False
    exclusive: bool = False
    match: bool = True
    sensitive: bool = False  # personal data: masked unless the caller holds ``pii:read``
    derived_from: str | None = None  # derive this identifier from another when absent
    derive: Literal["first_label"] | None = None

    @model_validator(mode="after")
    def _check(self) -> IdentifierDef:
        if not _PROP_RE.match(self.kind):
            raise ValueError(f"identifier kind '{self.kind}' must be snake_case")
        if (self.derived_from is None) != (self.derive is None):
            raise ValueError("'derived_from' and 'derive' must be set together")
        return self


class NodeTypeDef(_Strict):
    description: str = ""
    plane: Literal["cyber", "ai", "business", "threat"] = "cyber"
    identifiers: tuple[IdentifierDef, ...]
    properties: dict[str, PropertyDef] = Field(default_factory=dict)
    additional_properties: bool = True
    name_from: tuple[str, ...] = ()  # properties / identifier kinds tried in order for the display name
    ttl_days: int | None = None  # nodes not re-observed for this long are expired by maintenance

    def identifier(self, kind: str) -> IdentifierDef | None:
        for ident in self.identifiers:
            if ident.kind == kind:
                return ident
        return None


class EdgeTypeDef(_Strict):
    description: str = ""
    source: tuple[str, ...]
    target: tuple[str, ...]
    properties: dict[str, PropertyDef] = Field(default_factory=dict)
    additional_properties: bool = True
    ttl_days: int | None = None


# --------------------------------------------------------------------------- #
# Attack semantics
# --------------------------------------------------------------------------- #
class ProbabilityModel(_Strict):
    """How the success probability of one attack step is obtained.

    * ``fixed`` — a constant ``value``
    * ``by_property`` — looked up from an edge property via ``values`` (``default`` otherwise)
    * ``exploitability`` — noisy-OR over the destination's open, remotely
      exploitable findings (see docs/ANALYTICS_MATH.md), never below ``floor``
    """

    model: Literal["fixed", "by_property", "exploitability"]
    value: float | None = None
    property: str | None = None
    values: dict[str, float] | None = None
    default: float | None = None
    floor: float = 0.0

    @model_validator(mode="after")
    def _check(self) -> ProbabilityModel:
        def _p(name: str, v: float | None) -> None:
            if v is not None and not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")

        _p("value", self.value)
        _p("default", self.default)
        _p("floor", self.floor)
        for k, v in (self.values or {}).items():
            _p(f"values[{k}]", v)
        if self.model == "fixed" and self.value is None:
            raise ValueError("fixed probability needs 'value'")
        if self.model == "by_property" and (not self.property or self.values is None or self.default is None):
            raise ValueError("by_property probability needs 'property', 'values' and 'default'")
        return self


class TransitionRule(_Strict):
    """One class of attacker movement, derived from one edge type."""

    name: str
    description: str = ""
    edge: str
    attacker_moves: Literal["source_to_target", "target_to_source"] = "source_to_target"
    where: dict[str, Any] = Field(default_factory=dict)  # predicate on edge properties
    probability: ProbabilityModel
    mitigated_by: tuple[str, ...] = ()  # control types that reduce this step
    control_on: Literal["origin", "destination", "either"] = "destination"
    recommended_controls: tuple[str, ...] = ()


class EntryRule(_Strict):
    """Where an external attacker can start."""

    name: str
    description: str = ""
    node_type: str
    where: dict[str, Any] = Field(default_factory=dict)
    probability: ProbabilityModel
    mitigated_by: tuple[str, ...] = ()
    recommended_controls: tuple[str, ...] = ()
    enabled: bool = True


class ImpactModel(_Strict):
    property: str | None = None
    values: dict[str, float] = Field(default_factory=dict)
    default: float = 1.0


class TargetRule(_Strict):
    """What counts as a crown jewel, and how much it matters."""

    name: str
    node_type: str
    where: dict[str, Any] = Field(default_factory=dict)
    impact: ImpactModel = Field(default_factory=ImpactModel)


class ExploitabilityParams(_Strict):
    open_statuses: tuple[str, ...] = ("open", "in_progress", "reopened", "risk_accepted")
    kev_floor: float = 0.9
    epss_weight: float = 1.0
    cvss_vector_weight: float = 0.6
    cvss_score_weight: float = 0.3
    unknown_default: float = 0.05
    # Findings with no linked vulnerability (misconfigurations): probability by severity.
    severity_fallback: dict[str, float] = Field(
        default_factory=lambda: {"critical": 0.5, "high": 0.3, "medium": 0.15, "low": 0.05, "info": 0.0}
    )
    remote_vectors: tuple[str, ...] = ("network", "adjacent")
    unknown_vector_is_remote: bool = True
    max_probability: float = 0.99


class ControlParams(_Strict):
    default_effectiveness: dict[str, float] = Field(default_factory=dict)
    fallback_effectiveness: float = 0.5
    degraded_factor: float = 0.5
    active_statuses: tuple[str, ...] = ("active",)
    degraded_statuses: tuple[str, ...] = ("degraded",)
    detection_types: tuple[str, ...] = ()
    detection_base: float = 0.02  # per-attempt detection probability with no detective control
    detection_weight: float = 0.3  # share of a detective control's effectiveness realised per attempt
    max_combined_reduction: float = 0.99


class GraphBindings(_Strict):
    """Names of the ontology elements the analytics engine relies on."""

    finding_type: str = "Finding"
    vulnerability_type: str = "Vulnerability"
    control_type: str = "Control"
    has_finding_edge: str = "HAS_FINDING"
    instance_of_edge: str = "INSTANCE_OF"
    protects_edge: str = "PROTECTS"
    mitigates_edge: str = "MITIGATES"
    # Business impact: "X SUPPORTS S" and "S DEPENDS_ON X" both mean S needs X.
    supports_edges: tuple[str, ...] = ("SUPPORTS",)
    depends_on_edges: tuple[str, ...] = ("DEPENDS_ON",)


class AttackSemantics(_Strict):
    compromisable: tuple[str, ...]
    bindings: GraphBindings = Field(default_factory=GraphBindings)
    entries: tuple[EntryRule, ...] = ()
    transitions: tuple[TransitionRule, ...] = ()
    targets: tuple[TargetRule, ...] = ()
    exploitability: ExploitabilityParams = Field(default_factory=ExploitabilityParams)
    controls: ControlParams = Field(default_factory=ControlParams)


class OntologyMeta(_Strict):
    name: str
    version: str
    description: str = ""

    @model_validator(mode="after")
    def _semver(self) -> OntologyMeta:
        if not re.match(r"^\d+\.\d+\.\d+$", self.version):
            raise ValueError("ontology version must be semantic (MAJOR.MINOR.PATCH)")
        return self


class Ontology(_Strict):
    ontology: OntologyMeta
    node_types: dict[str, NodeTypeDef]
    edge_types: dict[str, EdgeTypeDef]
    attack_semantics: AttackSemantics

    # ------------------------------------------------------------------ #
    @property
    def name(self) -> str:
        return self.ontology.name

    @property
    def version(self) -> str:
        return self.ontology.version

    def node_type(self, name: str) -> NodeTypeDef | None:
        return self.node_types.get(name)

    def edge_type(self, name: str) -> EdgeTypeDef | None:
        return self.edge_types.get(name)

    def fingerprint(self) -> str:
        """Stable content hash, recorded with every ingest batch for lineage."""
        body = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def sensitive_properties(self) -> dict[str, frozenset[str]]:
        return {
            name: frozenset(p for p, d in nt.properties.items() if d.sensitive)
            for name, nt in self.node_types.items()
            if any(d.sensitive for d in nt.properties.values())
        }

    def sensitive_identifiers(self) -> dict[str, frozenset[str]]:
        return {
            name: frozenset(i.kind for i in nt.identifiers if i.sensitive)
            for name, nt in self.node_types.items()
            if any(i.sensitive for i in nt.identifiers)
        }

    # ------------------------------------------------------------------ #
    def check_integrity(self) -> None:
        """Cross-reference checks that a schema alone cannot express."""
        errors: list[str] = []

        for name, nt in self.node_types.items():
            if not _NAME_RE.match(name):
                errors.append(f"node type '{name}' must be PascalCase")
            if not nt.identifiers:
                errors.append(f"node type '{name}' needs at least one identifier")
            kinds = [i.kind for i in nt.identifiers]
            if len(set(kinds)) != len(kinds):
                errors.append(f"node type '{name}' has duplicate identifier kinds")
            if not any(not i.weak and i.match for i in nt.identifiers):
                errors.append(f"node type '{name}' needs at least one strong, matchable identifier")
            for ident in nt.identifiers:
                if ident.derived_from and ident.derived_from not in kinds:
                    errors.append(f"{name}.{ident.kind} derives from unknown identifier '{ident.derived_from}'")
            for prop in nt.properties:
                if not _PROP_RE.match(prop):
                    errors.append(f"property '{name}.{prop}' must be snake_case")
            for ref in nt.name_from:
                if ref not in nt.properties and ref not in kinds:
                    errors.append(f"{name}.name_from references unknown '{ref}'")

        for name, et in self.edge_types.items():
            if not _EDGE_RE.match(name):
                errors.append(f"edge type '{name}' must be UPPER_SNAKE_CASE")
            for side, types in (("source", et.source), ("target", et.target)):
                if not types:
                    errors.append(f"edge type '{name}' has no {side} types")
                for t in types:
                    if t not in self.node_types:
                        errors.append(f"edge type '{name}' {side} references unknown node type '{t}'")
            for prop in et.properties:
                if not _PROP_RE.match(prop):
                    errors.append(f"property '{name}.{prop}' must be snake_case")

        sem = self.attack_semantics
        for t in sem.compromisable:
            if t not in self.node_types:
                errors.append(f"attack_semantics.compromisable references unknown node type '{t}'")
        b = sem.bindings
        for label, t in (
            ("finding_type", b.finding_type),
            ("vulnerability_type", b.vulnerability_type),
            ("control_type", b.control_type),
        ):
            if t not in self.node_types:
                errors.append(f"attack_semantics.bindings.{label} references unknown node type '{t}'")
        for label, e in (
            ("has_finding_edge", b.has_finding_edge),
            ("instance_of_edge", b.instance_of_edge),
            ("protects_edge", b.protects_edge),
            ("mitigates_edge", b.mitigates_edge),
            *((f"supports_edges[{i}]", e) for i, e in enumerate(b.supports_edges)),
            *((f"depends_on_edges[{i}]", e) for i, e in enumerate(b.depends_on_edges)),
        ):
            if e not in self.edge_types:
                errors.append(f"attack_semantics.bindings.{label} references unknown edge type '{e}'")

        seen: set[str] = set()
        for rule in sem.transitions:
            if rule.name in seen:
                errors.append(f"duplicate transition rule '{rule.name}'")
            seen.add(rule.name)
            et2 = self.edge_types.get(rule.edge)
            if et2 is None:
                errors.append(f"transition '{rule.name}' references unknown edge type '{rule.edge}'")
                continue
            origin, dest = (
                (et2.source, et2.target)
                if rule.attacker_moves == "source_to_target"
                else (
                    et2.target,
                    et2.source,
                )
            )
            if not set(origin) & set(sem.compromisable):
                errors.append(f"transition '{rule.name}': no origin type of {rule.edge} is compromisable")
            if not set(dest) & set(sem.compromisable):
                errors.append(f"transition '{rule.name}': no destination type of {rule.edge} is compromisable")
            if rule.probability.model == "by_property" and rule.probability.property not in et2.properties:
                errors.append(
                    f"transition '{rule.name}': property '{rule.probability.property}' is not declared on {rule.edge}"
                )
        for entry in sem.entries:
            if entry.name in seen:
                errors.append(f"duplicate rule name '{entry.name}'")
            seen.add(entry.name)
            if entry.node_type not in sem.compromisable:
                errors.append(f"entry '{entry.name}': node type '{entry.node_type}' is not compromisable")
            if entry.probability.model == "by_property":
                errors.append(f"entry '{entry.name}': by_property is not valid for entry rules")
        for target in sem.targets:
            if target.node_type not in sem.compromisable:
                errors.append(f"target '{target.name}': node type '{target.node_type}' is not compromisable")

        if errors:
            raise OntologyError("ontology failed integrity checks", detail={"errors": errors})

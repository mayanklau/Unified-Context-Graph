"""Projection of the security graph into an attack graph.

The ontology's ``attack_semantics`` say which relationships let an attacker
move and with what probability. This module applies those rules to the stored
graph and produces a compact, array-backed attack graph:

* **states** — every node an attacker can hold (assets, identities, data
  stores, agents, tools, network positions) plus a virtual ``attacker`` state
* **steps** — one attacker movement between two states, with its success
  probability, the rule that produced it and the evidence behind it
* **gates** — for exploit steps, all routes into the same target share one
  random event ("is this target exploitable?"), so fifty neighbours attacking
  one host are not counted as fifty independent chances

Nothing here is learned or sampled: the same graph and the same ontology
always give the same attack graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from secgraph.analytics.exploitability import (
    ControlInfo,
    FindingExposure,
    combined_reduction,
    control_effectiveness,
    noisy_or,
    score_finding,
)
from secgraph.config import Settings
from secgraph.errors import LimitExceeded
from secgraph.ontology.model import AttackSemantics, EntryRule, Ontology, ProbabilityModel, TransitionRule
from secgraph.ontology.validate import matches
from secgraph.store.repository import GraphReader, chunked
from secgraph.store.types import utcnow

ATTACKER_ID = "attacker"
ATTACKER_INDEX = 0


@dataclass
class Expanded:
    """The attack graph with gates as vertices: the form the probability engines consume."""

    vertices: int
    src: np.ndarray
    dst: np.ndarray
    p: np.ndarray
    gate_position: np.ndarray  # gate id -> index of its ``gate → state`` edge in ``p`` (-1 if unused)


@dataclass
class AttackGraph:
    tenant_id: str
    built_at: datetime
    change_seq: int
    as_of: datetime | None
    ontology_version: str

    # states (index 0 is the external attacker)
    ids: list[str]
    types: list[str]
    names: list[str]
    index: dict[str, int]
    impact: np.ndarray  # 0.0 for states that are not targets
    target_rule: dict[int, str]
    detection: np.ndarray  # probability that one attempt made from this state is detected

    # steps (parallel arrays)
    step_src: np.ndarray
    step_dst: np.ndarray
    step_prob: np.ndarray
    step_rule: list[str]
    step_edge: list[str | None]
    step_gate: np.ndarray  # gate id, or -1 when the step has its own independent probability
    step_origin_factor: np.ndarray
    step_controls: list[tuple[ControlInfo, ...]]

    # gates
    gate_node: np.ndarray
    gate_rule: list[str]
    gate_prob: np.ndarray
    gate_floor: np.ndarray
    gate_reduction: np.ndarray
    gate_controls: list[tuple[ControlInfo, ...]]

    exposures: dict[int, list[FindingExposure]] = field(default_factory=dict)
    controls: dict[int, list[ControlInfo]] = field(default_factory=dict)
    _out: list[list[int]] | None = None
    _in: list[list[int]] | None = None
    _expanded: Expanded | None = None
    memo: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    @property
    def state_count(self) -> int:
        return len(self.ids)

    @property
    def step_count(self) -> int:
        return len(self.step_rule)

    @property
    def targets(self) -> list[int]:
        return [int(i) for i in np.nonzero(self.impact > 0)[0]]

    def out_steps(self) -> list[list[int]]:
        if self._out is None:
            out: list[list[int]] = [[] for _ in self.ids]
            for step, src in enumerate(self.step_src.tolist()):
                out[src].append(step)
            self._out = out
        return self._out

    def in_steps(self) -> list[list[int]]:
        if self._in is None:
            incoming: list[list[int]] = [[] for _ in self.ids]
            for step, dst in enumerate(self.step_dst.tolist()):
                incoming[dst].append(step)
            self._in = incoming
        return self._in

    def gate_probabilities(self, without_findings: frozenset[str] = frozenset()) -> np.ndarray:
        """Gate probabilities, optionally recomputed as if some findings were remediated."""
        if not without_findings:
            return self.gate_prob
        probabilities = self.gate_prob.copy()
        for gate, node in enumerate(self.gate_node.tolist()):
            exposures = self.exposures.get(node, ())
            if not any(e.finding_id in without_findings for e in exposures):
                continue
            remaining = [e.probability for e in exposures if e.remote and e.finding_id not in without_findings]
            raw = max(float(self.gate_floor[gate]), noisy_or(remaining))
            probabilities[gate] = raw * float(self.gate_reduction[gate])
        return probabilities

    def expand(self) -> Expanded:
        """Turn gates into explicit vertices so shared exploit events are modelled once.

        Vertices ``0 .. state_count-1`` are states; vertex ``state_count + g`` is gate ``g``.
        A gated step ``u → v`` becomes ``u → gate`` (the route's own factor) and one shared
        ``gate → v`` edge carrying the target's exploitability.
        """
        if self._expanded is not None:
            return self._expanded
        n = self.state_count
        gated = self.step_gate >= 0
        used = np.unique(self.step_gate[gated])
        src = np.concatenate([self.step_src[~gated], self.step_src[gated], n + used])
        dst = np.concatenate([self.step_dst[~gated], n + self.step_gate[gated], self.gate_node[used]])
        p = np.concatenate([self.step_prob[~gated], self.step_origin_factor[gated], self.gate_prob[used]])
        gate_position = np.full(len(self.gate_rule), -1, dtype=np.int64)
        gate_position[used] = int((~gated).sum() + gated.sum()) + np.arange(used.size)
        self._expanded = Expanded(
            vertices=n + len(self.gate_rule),
            src=src.astype(np.int64),
            dst=dst.astype(np.int64),
            p=p.astype(np.float64),
            gate_position=gate_position,
        )
        return self._expanded

    def step_probabilities(self, gate_prob: np.ndarray | None = None) -> np.ndarray:
        """Full probability of each step (origin factor × gate probability for gated steps)."""
        if gate_prob is None:
            return self.step_prob
        probabilities = self.step_prob.copy()
        gated = self.step_gate >= 0
        probabilities[gated] = self.step_origin_factor[gated] * gate_prob[self.step_gate[gated]]
        return probabilities


class _Builder:
    def __init__(self, reader: GraphReader, ontology: Ontology, settings: Settings, as_of: datetime | None):
        self.reader = reader
        self.ontology = ontology
        self.sem: AttackSemantics = ontology.attack_semantics
        self.settings = settings
        self.as_of = as_of
        self.ids: list[str] = [ATTACKER_ID]
        self.types: list[str] = ["Attacker"]
        self.names: list[str] = ["External attacker"]
        self.index: dict[str, int] = {ATTACKER_ID: ATTACKER_INDEX}
        self.impact: list[float] = [0.0]
        self.target_rule: dict[int, str] = {}
        self.entry_matches: list[tuple[EntryRule, int]] = []
        self.controls: dict[int, list[ControlInfo]] = {}
        self.exposures: dict[int, list[FindingExposure]] = {}
        # steps keyed by (origin, destination, rule) so parallel edges collapse to the strongest
        self.steps: dict[tuple[int, int, str], tuple[float, str | None, int, float, tuple[ControlInfo, ...]]] = {}
        self.gates: dict[tuple[int, str], int] = {}
        self.gate_node: list[int] = []
        self.gate_rule: list[str] = []
        self.gate_prob: list[float] = []
        self.gate_floor: list[float] = []
        self.gate_reduction: list[float] = []
        self.gate_controls: list[tuple[ControlInfo, ...]] = []

    # ------------------------------------------------------------------ #
    def load_states(self) -> None:
        sem = self.sem
        limit = self.settings.analytics_max_nodes
        for record in self.reader.iter_nodes(list(sem.compromisable), as_of=self.as_of):
            if len(self.ids) > limit:
                raise LimitExceeded(
                    f"the attack graph has more than {limit} states; raise SECGRAPH_ANALYTICS_MAX_NODES "
                    "or analyse a smaller scope"
                )
            idx = len(self.ids)
            self.ids.append(record.id)
            self.types.append(record.type)
            self.names.append(record.name)
            self.index[record.id] = idx
            best, best_rule = 0.0, None
            for rule in sem.targets:
                if rule.node_type != record.type or not matches(record.properties, rule.where):
                    continue
                value = rule.impact.default
                if rule.impact.property:
                    raw = record.properties.get(rule.impact.property)
                    value = rule.impact.values.get(str(raw), rule.impact.default) if raw is not None else value
                if value > best:
                    best, best_rule = float(value), rule.name
            self.impact.append(best)
            if best_rule is not None:
                self.target_rule[idx] = best_rule
            for entry in sem.entries:
                if entry.enabled and entry.node_type == record.type and matches(record.properties, entry.where):
                    self.entry_matches.append((entry, idx))

    def load_controls(self) -> dict[str, list[ControlInfo]]:
        """Fill ``self.controls`` (by protected state) and return compensating controls by target id."""
        b = self.sem.bindings
        params = self.sem.controls
        instances: dict[str, ControlInfo] = {}
        for record in self.reader.iter_nodes([b.control_type], as_of=self.as_of):
            effectiveness = control_effectiveness(record.properties, params)
            if effectiveness <= 0.0:
                continue
            instances[record.id] = ControlInfo(
                id=record.id,
                name=record.name,
                control_type=str(record.properties.get("control_type") or "other"),
                effectiveness=effectiveness,
            )
        mitigates: dict[str, list[ControlInfo]] = {}
        if not instances:
            return mitigates
        for _lineage, edge_type, src, dst, _props in self.reader.iter_edges(
            [b.protects_edge, b.mitigates_edge], as_of=self.as_of
        ):
            control = instances.get(src)
            if control is None:
                continue
            if edge_type == b.protects_edge:
                idx = self.index.get(dst)
                if idx is not None:
                    self.controls.setdefault(idx, []).append(control)
            else:
                mitigates.setdefault(dst, []).append(control)
        return mitigates

    def load_exposures(self, mitigates: dict[str, list[ControlInfo]]) -> None:
        b = self.sem.bindings
        params = self.sem.exploitability
        finding_def = self.ontology.node_types[b.finding_type]
        where: dict[str, Any] | None = None
        status_def = finding_def.properties.get("status")
        if status_def is not None and status_def.values:
            closed = [v for v in status_def.values if v not in params.open_statuses]
            if closed:
                where = {"status": {"nin": closed}}
        findings: dict[str, tuple[str, dict[str, Any]]] = {}
        for record in self.reader.iter_nodes([b.finding_type], as_of=self.as_of, where=where):
            status = record.properties.get("status", "open")
            if status in params.open_statuses:
                findings[record.id] = (record.name, record.properties)
        if not findings:
            return
        located: dict[str, list[int]] = {}
        instance_of: dict[str, str] = {}
        for _lineage, edge_type, src, dst, _props in self.reader.iter_edges(
            [b.has_finding_edge, b.instance_of_edge], as_of=self.as_of
        ):
            if edge_type == b.has_finding_edge:
                idx = self.index.get(src)
                if idx is not None and dst in findings:
                    located.setdefault(dst, []).append(idx)
            elif src in findings:
                instance_of.setdefault(src, dst)
        vulnerability_ids = sorted({v for f, v in instance_of.items() if f in located})
        vulnerabilities: dict[str, tuple[str, dict[str, Any]]] = {}
        for chunk in chunked(vulnerability_ids):
            for vid, record in self.reader.get_nodes(chunk, as_of=self.as_of).items():
                vulnerabilities[vid] = (record.name, record.properties)
        for finding_id, holders in located.items():
            name, properties = findings[finding_id]
            vulnerability_id = instance_of.get(finding_id)
            vulnerability = vulnerabilities.get(vulnerability_id) if vulnerability_id else None
            compensating = list(mitigates.get(finding_id, ()))
            if vulnerability_id:
                compensating.extend(mitigates.get(vulnerability_id, ()))
            exposure = score_finding(
                finding_id,
                properties,
                vulnerability_id if vulnerability else None,
                vulnerability[0] if vulnerability else None,
                vulnerability[1] if vulnerability else None,
                compensating,
                params,
                self.sem.controls,
                fallback_title=name,
            )
            for idx in holders:
                self.exposures.setdefault(idx, []).append(exposure)
        for exposures in self.exposures.values():
            exposures.sort(key=lambda e: (-e.probability, e.finding_id))

    # ------------------------------------------------------------------ #
    def _applicable(self, idx: int, control_types: tuple[str, ...]) -> list[ControlInfo]:
        if not control_types:
            return []
        wanted = set(control_types)
        return [c for c in self.controls.get(idx, ()) if c.control_type in wanted]

    def _gate(self, destination: int, rule_name: str, model: ProbabilityModel, mitigated_by: tuple[str, ...]) -> int:
        key = (destination, rule_name)
        gate = self.gates.get(key)
        if gate is None:
            remote = [e.probability for e in self.exposures.get(destination, ()) if e.remote]
            controls = tuple(self._applicable(destination, mitigated_by))
            reduction = combined_reduction(list(controls), self.sem.controls)
            raw = max(model.floor, noisy_or(remote))
            gate = len(self.gate_node)
            self.gates[key] = gate
            self.gate_node.append(destination)
            self.gate_rule.append(rule_name)
            self.gate_floor.append(model.floor)
            self.gate_reduction.append(reduction)
            self.gate_prob.append(raw * reduction)
            self.gate_controls.append(controls)
        return gate

    def _add_step(
        self,
        origin: int,
        destination: int,
        rule_name: str,
        model: ProbabilityModel,
        mitigated_by: tuple[str, ...],
        control_on: str,
        edge_id: str | None,
        edge_properties: dict[str, Any],
    ) -> None:
        if origin == destination:
            return
        origin_controls = self._applicable(origin, mitigated_by) if control_on in ("origin", "either") else []
        destination_controls = (
            self._applicable(destination, mitigated_by) if control_on in ("destination", "either") else []
        )
        if model.model == "exploitability":
            # The destination's own controls belong to the shared gate; origin-side controls to this route.
            gate = self._gate(destination, rule_name, model, mitigated_by if destination_controls else ())
            gate_probability = self.gate_prob[gate]
            if gate_probability <= 0.0:
                return
            factor = combined_reduction(origin_controls, self.sem.controls)
            probability = factor * gate_probability
            applied = tuple(origin_controls) + self.gate_controls[gate]
        else:
            gate = -1
            if model.model == "fixed":
                base = float(model.value or 0.0)
            else:
                raw = edge_properties.get(model.property or "")
                base = (
                    float((model.values or {}).get(str(raw), model.default or 0.0))
                    if raw is not None
                    else float(model.default or 0.0)
                )
            seen: dict[str, ControlInfo] = {}
            for control in (*origin_controls, *destination_controls):
                seen.setdefault(control.id, control)
            applied = tuple(seen.values())
            factor = combined_reduction(list(applied), self.sem.controls)
            probability = base * factor
        if probability <= 0.0:
            return
        key = (origin, destination, rule_name)
        current = self.steps.get(key)
        if current is None or probability > current[0]:
            self.steps[key] = (probability, edge_id, gate, factor, applied)

    def load_transitions(self) -> None:
        rules_by_edge: dict[str, list[TransitionRule]] = {}
        for rule in self.sem.transitions:
            rules_by_edge.setdefault(rule.edge, []).append(rule)
        edge_types = sorted(rules_by_edge)
        total = self.reader.count_edges(edge_types) if self.as_of is None else 0
        if total > self.settings.analytics_max_edges:
            raise LimitExceeded(
                f"{total} relationships feed the attack graph; the limit is "
                f"{self.settings.analytics_max_edges} (SECGRAPH_ANALYTICS_MAX_EDGES)"
            )
        for lineage, edge_type, src, dst, properties in self.reader.iter_edges(edge_types, as_of=self.as_of):
            source, target = self.index.get(src), self.index.get(dst)
            if source is None or target is None:
                continue
            for rule in rules_by_edge[edge_type]:
                if rule.where and not matches(properties, rule.where):
                    continue
                origin, destination = (
                    (source, target) if rule.attacker_moves == "source_to_target" else (target, source)
                )
                self._add_step(
                    origin,
                    destination,
                    rule.name,
                    rule.probability,
                    rule.mitigated_by,
                    rule.control_on,
                    lineage,
                    properties,
                )

    def load_entries(self) -> None:
        for rule, idx in self.entry_matches:
            self._add_step(ATTACKER_INDEX, idx, rule.name, rule.probability, rule.mitigated_by, "destination", None, {})

    def detection(self) -> np.ndarray:
        params = self.sem.controls
        detective = set(params.detection_types)
        values = np.full(len(self.ids), params.detection_base, dtype=np.float64)
        for idx, controls in self.controls.items():
            miss = 1.0 - params.detection_base
            for control in controls:
                if control.control_type in detective:
                    miss *= 1.0 - params.detection_weight * control.effectiveness
            values[idx] = 1.0 - miss
        values[ATTACKER_INDEX] = 0.0  # attempts launched from outside are not detected "at" the attacker
        return values

    def finish(self, tenant_id: str, change_seq: int) -> AttackGraph:
        keys = sorted(self.steps)  # deterministic step order
        count = len(keys)
        step_src = np.fromiter((k[0] for k in keys), dtype=np.int64, count=count)
        step_dst = np.fromiter((k[1] for k in keys), dtype=np.int64, count=count)
        values = [self.steps[k] for k in keys]
        return AttackGraph(
            tenant_id=tenant_id,
            built_at=utcnow(),
            change_seq=change_seq,
            as_of=self.as_of,
            ontology_version=self.ontology.version,
            ids=self.ids,
            types=self.types,
            names=self.names,
            index=self.index,
            impact=np.asarray(self.impact, dtype=np.float64),
            target_rule=self.target_rule,
            detection=self.detection(),
            step_src=step_src,
            step_dst=step_dst,
            step_prob=np.fromiter((v[0] for v in values), dtype=np.float64, count=count),
            step_rule=[k[2] for k in keys],
            step_edge=[v[1] for v in values],
            step_gate=np.fromiter((v[2] for v in values), dtype=np.int64, count=count),
            step_origin_factor=np.fromiter((v[3] for v in values), dtype=np.float64, count=count),
            step_controls=[v[4] for v in values],
            gate_node=np.asarray(self.gate_node, dtype=np.int64),
            gate_rule=self.gate_rule,
            gate_prob=np.asarray(self.gate_prob, dtype=np.float64),
            gate_floor=np.asarray(self.gate_floor, dtype=np.float64),
            gate_reduction=np.asarray(self.gate_reduction, dtype=np.float64),
            gate_controls=self.gate_controls,
            exposures=self.exposures,
            controls=self.controls,
        )


def build_attack_graph(
    reader: GraphReader,
    ontology: Ontology,
    settings: Settings,
    *,
    change_seq: int = 0,
    as_of: datetime | None = None,
) -> AttackGraph:
    builder = _Builder(reader, ontology, settings, as_of)
    builder.load_states()
    mitigates = builder.load_controls()
    builder.load_exposures(mitigates)
    builder.load_transitions()
    builder.load_entries()
    return builder.finish(reader.tenant_id, change_seq)

"""Analytics API: attack paths, compromise probability, blast radius, prioritisation.

Every number returned here can be traced to its inputs: each path step names
the rule that produced it, the findings and controls behind its probability,
and the ontology parameters used. ``parameters()`` returns those parameters so
a front end can show the logic next to the result.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import numpy as np

from secgraph.analytics.attack_graph import ATTACKER_INDEX, AttackGraph, build_attack_graph
from secgraph.analytics.exploitability import noisy_or
from secgraph.analytics.markov import absorbing_chain
from secgraph.analytics.paths import Path, k_best_paths, step_costs
from secgraph.analytics.probability import (
    backward_reachable,
    best_path_tree,
    estimate_reach,
    forward_reachable,
    noisy_or_bound,
)
from secgraph.config import Settings
from secgraph.errors import NotFound, ValidationFailed
from secgraph.events.outbox import head_sequence
from secgraph.governance.rbac import AccessScope
from secgraph.observability import ANALYTICS_CACHE, ANALYTICS_SECONDS, timed
from secgraph.ontology.model import EntryRule, Ontology, TransitionRule
from secgraph.query.views import Viewer
from secgraph.store.db import Database
from secgraph.store.repository import GraphReader
from secgraph.store.types import utcnow

_MAX_K = 25
_MIN_PATH_PROBABILITY = 1e-9


def _round(value: float, digits: int = 6) -> float:
    return round(float(value), digits)


@dataclass
class _Baseline:
    """Quantities computed once per attack graph and reused by every analytic."""

    fwd: np.ndarray  # expanded vertices reachable from the attacker
    edge_index: np.ndarray  # expanded edges that lie on some attacker → target route
    upper: np.ndarray  # per state
    costs: list[float]  # -log p per step
    lower_cost: list[float]  # best-path cost per state
    lower_parent: list[int]  # best-path incoming step per state
    step_src: list[int]
    step_dst: list[int]


class AnalyticsService:
    def __init__(self, db: Database, ontology: Ontology, settings: Settings):
        self.db = db
        self.ontology = ontology
        self.settings = settings
        self.sem = ontology.attack_semantics
        self._rules: dict[str, TransitionRule | EntryRule] = {
            rule.name: rule for rule in (*self.sem.transitions, *self.sem.entries)
        }
        self._graphs: dict[str, AttackGraph] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    # ------------------------------------------------------------------ #
    # Attack graph cache
    # ------------------------------------------------------------------ #
    def _lock(self, tenant_id: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(tenant_id, threading.Lock())

    def graph(self, tenant_id: str, *, as_of: datetime | None = None, refresh: bool = False) -> AttackGraph:
        """The tenant's attack graph: rebuilt when the graph has changed, reused otherwise."""
        if as_of is not None:
            with timed(ANALYTICS_SECONDS, operation="build"), self.db.snapshot() as session:
                return build_attack_graph(GraphReader(session, tenant_id), self.ontology, self.settings, as_of=as_of)
        with self._lock(tenant_id):
            cached = self._graphs.get(tenant_id)
            with self.db.snapshot() as session:
                seq = head_sequence(session, tenant_id)
                if cached is not None and not refresh:
                    age = (utcnow() - cached.built_at).total_seconds()
                    if cached.change_seq == seq or age < self.settings.analytics_cache_ttl_seconds:
                        ANALYTICS_CACHE.labels(result="hit").inc()
                        return cached
                ANALYTICS_CACHE.labels(result="miss").inc()
                with timed(ANALYTICS_SECONDS, operation="build"):
                    graph = build_attack_graph(
                        GraphReader(session, tenant_id), self.ontology, self.settings, change_seq=seq
                    )
            self._graphs[tenant_id] = graph
            return graph

    def invalidate(self, tenant_id: str | None = None) -> None:
        with self._guard:
            if tenant_id is None:
                self._graphs.clear()
            else:
                self._graphs.pop(tenant_id, None)

    # ------------------------------------------------------------------ #
    # Shared computations
    # ------------------------------------------------------------------ #
    def _baseline(self, graph: AttackGraph) -> _Baseline:
        cached = graph.memo.get("baseline")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        ex = graph.expand()
        n = graph.state_count
        fwd = forward_reachable(ex.vertices, ex.src, ex.dst, ex.p, [ATTACKER_INDEX])
        targets = graph.targets
        if targets:
            bwd = backward_reachable(ex.vertices, ex.src, ex.dst, ex.p, targets)
            edge_index = np.flatnonzero(fwd[ex.src] & bwd[ex.dst] & (ex.p > 0.0))
        else:
            edge_index = np.zeros(0, dtype=np.int64)
        upper_full, _ = noisy_or_bound(ex.vertices, ex.src[edge_index], ex.dst[edge_index], ex.p[edge_index])
        costs = step_costs(graph.step_prob)
        step_dst = graph.step_dst.tolist()
        lower_cost, lower_parent = best_path_tree(n, graph.out_steps(), step_dst, costs, ATTACKER_INDEX)
        baseline = _Baseline(
            fwd=fwd,
            edge_index=edge_index,
            upper=upper_full[:n],
            costs=costs,
            lower_cost=lower_cost,
            lower_parent=lower_parent,
            step_src=graph.step_src.tolist(),
            step_dst=step_dst,
        )
        graph.memo["baseline"] = baseline
        return baseline

    def _upper_risk(self, graph: AttackGraph, base: _Baseline, p: np.ndarray) -> tuple[float, np.ndarray]:
        """Risk = Σ impact × P(compromise) under the noisy-OR bound, for modified edge probabilities."""
        ex = graph.expand()
        idx = base.edge_index
        upper, _ = noisy_or_bound(ex.vertices, ex.src[idx], ex.dst[idx], p[idx])
        upper = upper[: graph.state_count]
        return float(graph.impact @ upper), upper

    def _estimate_targets(self, graph: AttackGraph, base: _Baseline) -> tuple[np.ndarray, np.ndarray, str, int]:
        cached = graph.memo.get("estimate")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        ex = graph.expand()
        idx = base.edge_index
        result = estimate_reach(
            ex.vertices,
            ex.src[idx],
            ex.dst[idx],
            ex.p[idx],
            samples=self.settings.analytics_mc_samples,
            seed=self.settings.analytics_seed,
            budget=self.settings.analytics_mc_budget,
        )
        n = graph.state_count
        value = (result.probability[:n], result.stderr[:n], result.method, result.samples)
        graph.memo["estimate"] = value
        return value

    # ------------------------------------------------------------------ #
    # Presentation helpers
    # ------------------------------------------------------------------ #
    def _meta(self, graph: AttackGraph) -> dict[str, Any]:
        return {
            "states": graph.state_count - 1,
            "steps": graph.step_count,
            "built_at": graph.built_at.isoformat(),
            "as_of": graph.as_of.isoformat() if graph.as_of else None,
            "change_seq": graph.change_seq,
            "ontology_version": graph.ontology_version,
        }

    def _node(self, graph: AttackGraph, viewer: Viewer, idx: int) -> dict[str, Any]:
        node_type = graph.types[idx]
        out: dict[str, Any] = {
            "id": graph.ids[idx],
            "type": node_type,
            "name": viewer.display_name(node_type, graph.ids[idx], graph.names[idx]),
        }
        impact = float(graph.impact[idx])
        if impact > 0:
            out["impact"] = impact
            out["target_rule"] = graph.target_rule.get(idx)
        return out

    def _explain_step(
        self, graph: AttackGraph, viewer: Viewer, step: int, probability: float | None = None
    ) -> dict[str, Any]:
        rule = self._rules[graph.step_rule[step]]
        model = rule.probability
        p = float(graph.step_prob[step]) if probability is None else probability
        origin, destination = int(graph.step_src[step]), int(graph.step_dst[step])
        applied = graph.step_controls[step]
        basis: dict[str, Any] = {"model": model.model}
        if model.model == "exploitability":
            gate = int(graph.step_gate[step])
            remote = [e for e in graph.exposures.get(destination, ()) if e.remote]
            combined = noisy_or([e.probability for e in remote])
            basis.update(
                findings=[e.as_dict() for e in remote[:5]],
                finding_count=len(remote),
                combined_exploitability=_round(combined),
                floor=model.floor,
                control_multiplier=_round(float(graph.gate_reduction[gate]) * float(graph.step_origin_factor[step])),
                formula="max(floor, 1 - Π(1 - p_finding)) × Π(1 - control effectiveness)",
            )
        else:
            multiplier = 1.0
            for control in applied:
                multiplier *= 1.0 - control.effectiveness
            multiplier = max(multiplier, 1.0 - self.sem.controls.max_combined_reduction)
            basis.update(
                base=_round(p / multiplier) if multiplier > 0 else None,
                control_multiplier=_round(multiplier),
                formula="base × Π(1 - control effectiveness)",
            )
            if model.model == "by_property":
                basis["property"] = model.property
        have = {c.control_type for c in applied}
        recommended = [c for c in (rule.recommended_controls or rule.mitigated_by) if c not in have]
        return {
            "from": self._node(graph, viewer, origin),
            "to": self._node(graph, viewer, destination),
            "technique": rule.name,
            "description": rule.description,
            "probability": _round(p),
            "edge_id": graph.step_edge[step],
            "basis": basis,
            "controls_applied": [c.as_dict() for c in applied],
            "recommended_controls": recommended,
        }

    def _path_view(
        self, graph: AttackGraph, viewer: Viewer, path: Path, *, rank: int, step_probabilities: np.ndarray | None = None
    ) -> dict[str, Any]:
        target = path.nodes[-1]
        probability = path.probability
        impact = float(graph.impact[target])
        probabilities = graph.step_prob if step_probabilities is None else step_probabilities
        return {
            "rank": rank,
            "target": self._node(graph, viewer, target),
            "probability": _round(probability),
            "risk": _round(probability * impact) if impact > 0 else None,
            "length": len(path.steps),
            "steps": [self._explain_step(graph, viewer, s, float(probabilities[s])) for s in path.steps],
        }

    @staticmethod
    def _trace(cost: list[float], parent: list[int], step_src: list[int], source: int, target: int) -> Path | None:
        """Rebuild the best path to ``target`` from a Dijkstra tree rooted at ``source``."""
        if math.isinf(cost[target]):
            return None
        steps: list[int] = []
        nodes: list[int] = [target]
        cursor = target
        while cursor != source:
            step = parent[cursor]
            if step < 0:
                return None
            steps.append(step)
            cursor = step_src[step]
            nodes.append(cursor)
        return Path(tuple(reversed(steps)), tuple(reversed(nodes)), cost[target])

    def _path_from_tree(self, base: _Baseline, target: int) -> Path | None:
        return self._trace(base.lower_cost, base.lower_parent, base.step_src, ATTACKER_INDEX, target)

    def _index(self, graph: AttackGraph, node_id: str, label: str) -> int:
        idx = graph.index.get(node_id)
        if idx is None or idx == ATTACKER_INDEX:
            raise NotFound(
                f"{label} {node_id} is not part of the attack graph (it does not exist, or its type is not one an "
                f"attacker can hold: {', '.join(self.sem.compromisable)})"
            )
        return idx

    def _probability_view(
        self, base: _Baseline, idx: int, estimate: tuple[np.ndarray, np.ndarray, str, int] | None
    ) -> dict[str, Any]:
        lower = math.exp(-base.lower_cost[idx]) if math.isfinite(base.lower_cost[idx]) else 0.0
        out: dict[str, Any] = {"lower": _round(lower), "upper": _round(max(float(base.upper[idx]), lower))}
        if estimate is not None:
            values, stderr, method, samples = estimate
            # The estimate is clamped into its proven bounds; sampling noise must never contradict them.
            out["estimate"] = _round(min(max(float(values[idx]), out["lower"]), out["upper"]))
            out["stderr"] = _round(float(stderr[idx]))
            out["method"] = method
            if samples:
                out["samples"] = samples
        return out

    # ------------------------------------------------------------------ #
    # Public analytics
    # ------------------------------------------------------------------ #
    def overview(
        self, tenant_id: str, scope: AccessScope, *, limit: int = 10, estimate: bool = True,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Where the organisation stands: entry points, crown jewels at risk and expected impact."""
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="overview"):
            viewer = Viewer(self.ontology, scope)
            base = self._baseline(graph)
            est = self._estimate_targets(graph, base) if estimate else None
            targets = graph.targets
            rows = []
            for idx in targets:
                view = self._probability_view(base, idx, est)
                headline = view.get("estimate", view["upper"])
                rows.append((headline * float(graph.impact[idx]), idx, view))
            rows.sort(key=lambda r: (-r[0], graph.ids[r[1]]))
            risk = {
                "lower": _round(sum(r[2]["lower"] * float(graph.impact[r[1]]) for r in rows)),
                "upper": _round(sum(r[2]["upper"] * float(graph.impact[r[1]]) for r in rows)),
            }
            if est is not None:
                risk["estimate"] = _round(sum(r[2]["estimate"] * float(graph.impact[r[1]]) for r in rows))
            exposures = [e for items in graph.exposures.values() for e in items]
            entry_steps = [s for s in graph.out_steps()[ATTACKER_INDEX]]
            return {
                "graph": self._meta(graph),
                "entry_points": len({int(graph.step_dst[s]) for s in entry_steps}),
                "targets": len(targets),
                "targets_at_risk": sum(1 for r in rows if r[2]["upper"] > 0),
                "total_impact": _round(float(graph.impact.sum())),
                "risk": risk,
                "top_targets": [
                    {**self._node(graph, viewer, idx), "probability": view, "expected_impact": _round(expected)}
                    for expected, idx, view in rows[: max(1, min(limit, 100))]
                ],
                "exposure": {
                    "open_findings": len({e.finding_id for e in exposures}),
                    "known_exploited": len({e.finding_id for e in exposures if e.kev}),
                    "risk_accepted": len({e.finding_id for e in exposures if e.status == "risk_accepted"}),
                    "states_with_findings": len(graph.exposures),
                },
            }

    def attack_paths(
        self,
        tenant_id: str,
        scope: AccessScope,
        *,
        target_id: str | None = None,
        source_id: str | None = None,
        k: int = 5,
        limit: int = 10,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Most probable attack paths.

        With ``target_id``: the ``k`` most probable loop-free paths to that node.
        Without: the single most probable path to each crown jewel, ranked by
        probability × impact. ``source_id`` starts from an assumed foothold
        instead of the external attacker.
        """
        if not 1 <= k <= _MAX_K:
            raise ValidationFailed(f"k must be between 1 and {_MAX_K}")
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="attack_paths"):
            viewer = Viewer(self.ontology, scope)
            base = self._baseline(graph)
            n = graph.state_count
            source = ATTACKER_INDEX if source_id is None else self._index(graph, source_id, "source")
            adjacency = graph.out_steps()
            max_cost = -math.log(_MIN_PATH_PROBABILITY)
            paths: list[Path] = []
            if target_id is not None:
                target = self._index(graph, target_id, "target")
                if target == source:
                    raise ValidationFailed("source and target are the same node")
                allowed = backward_reachable(n, graph.step_src, graph.step_dst, graph.step_prob, [target])
                paths = k_best_paths(
                    n, adjacency, base.step_src, base.step_dst, base.costs, source, target, k,
                    allowed=allowed, max_cost=max_cost,
                )
            else:
                if source == ATTACKER_INDEX:
                    cost, parent = base.lower_cost, base.lower_parent
                else:
                    cost, parent = best_path_tree(n, adjacency, base.step_dst, base.costs, source)
                ranked = []
                for target in graph.targets:
                    if target == source or not math.isfinite(cost[target]) or cost[target] > max_cost:
                        continue
                    ranked.append((math.exp(-cost[target]) * float(graph.impact[target]), target))
                ranked.sort(key=lambda r: (-r[0], graph.ids[r[1]]))
                for _risk, target in ranked[: max(1, min(limit, 100))]:
                    found = self._trace(cost, parent, base.step_src, source, target)
                    if found is not None:
                        paths.append(found)
            views = [self._path_view(graph, viewer, path, rank=i + 1) for i, path in enumerate(paths)]
            if source == ATTACKER_INDEX and views:
                est = self._estimate_targets(graph, base)
                for view, path in zip(views, paths, strict=True):
                    view["target_compromise"] = self._probability_view(base, path.nodes[-1], est)
            return {
                "graph": self._meta(graph),
                "source": self._node(graph, viewer, source) if source != ATTACKER_INDEX else {
                    "id": None, "type": "Attacker", "name": "External attacker"},
                "paths": views,
                "note": (
                    "Path probability is the product of its step probabilities. "
                    "'target_compromise' combines every route to the target: lower = best single path, "
                    "upper = noisy-OR bound, estimate = seeded Monte Carlo (or exact enumeration on small graphs)."
                ),
            }

    def node_exposure(
        self, tenant_id: str, scope: AccessScope, node_id: str, *, as_of: datetime | None = None
    ) -> dict[str, Any]:
        """Everything the attack model knows about one node: how likely, through what, leading where."""
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="node_exposure"):
            viewer = Viewer(self.ontology, scope)
            idx = self._index(graph, node_id, "node")
            base = self._baseline(graph)
            n = graph.state_count
            # Probability of reaching *this* node: the target-pruned baseline may not cover it.
            ex = graph.expand()
            bwd = backward_reachable(ex.vertices, ex.src, ex.dst, ex.p, [idx])
            edges = np.flatnonzero(base.fwd[ex.src] & bwd[ex.dst] & (ex.p > 0.0))
            upper, _ = noisy_or_bound(ex.vertices, ex.src[edges], ex.dst[edges], ex.p[edges])
            lower = math.exp(-base.lower_cost[idx]) if math.isfinite(base.lower_cost[idx]) else 0.0
            est = estimate_reach(
                ex.vertices, ex.src[edges], ex.dst[edges], ex.p[edges],
                samples=self.settings.analytics_mc_samples, seed=self.settings.analytics_seed,
                budget=self.settings.analytics_mc_budget,
            )
            probability = {
                "lower": _round(lower),
                "upper": _round(max(float(upper[idx]), lower)),
                "estimate": _round(min(max(float(est.probability[idx]), lower), max(float(upper[idx]), lower))),
                "stderr": _round(float(est.stderr[idx])),
                "method": est.method,
            }
            inbound = self._path_from_tree(base, idx)
            cost, parent = best_path_tree(n, graph.out_steps(), base.step_dst, base.costs, idx)
            onward = []
            for target in graph.targets:
                if target != idx and math.isfinite(cost[target]):
                    p = math.exp(-cost[target])
                    onward.append((p * float(graph.impact[target]), p, target))
            onward.sort(key=lambda r: (-r[0], graph.ids[r[2]]))
            exposures = graph.exposures.get(idx, [])
            return {
                "graph": self._meta(graph),
                "node": self._node(graph, viewer, idx),
                "is_entry_point": any(int(graph.step_dst[s]) == idx for s in graph.out_steps()[ATTACKER_INDEX]),
                "compromise_probability": probability,
                "most_likely_path": self._path_view(graph, viewer, inbound, rank=1) if inbound else None,
                "open_findings": [e.as_dict() for e in exposures[:25]],
                "open_finding_count": len(exposures),
                "controls": [c.as_dict() for c in graph.controls.get(idx, [])],
                "detection_per_attempt": _round(float(graph.detection[idx])),
                "targets_reachable": [
                    {**self._node(graph, viewer, target), "path_probability": _round(p)}
                    for _risk, p, target in onward[:10]
                ],
                "targets_reachable_count": len(onward),
            }

    def blast_radius(
        self,
        tenant_id: str,
        scope: AccessScope,
        node_id: str,
        *,
        limit: int = 50,
        min_probability: float = 0.01,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Assume this node is compromised: what can the attacker reach next, and which services suffer."""
        if not 0.0 <= min_probability <= 1.0:
            raise ValidationFailed("min_probability must be within [0, 1]")
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="blast_radius"):
            viewer = Viewer(self.ontology, scope)
            origin = self._index(graph, node_id, "node")
            base = self._baseline(graph)
            ex = graph.expand()
            n = graph.state_count
            # Replace the external attacker's entry steps with a certain foothold on the origin.
            keep = ex.src != ATTACKER_INDEX
            src = np.concatenate([ex.src[keep], [ATTACKER_INDEX]])
            dst = np.concatenate([ex.dst[keep], [origin]])
            p = np.concatenate([ex.p[keep], [1.0]])
            upper, _ = noisy_or_bound(ex.vertices, src, dst, p)
            est = estimate_reach(
                ex.vertices, src, dst, p,
                samples=self.settings.analytics_mc_samples, seed=self.settings.analytics_seed,
                budget=self.settings.analytics_mc_budget,
            )
            cost, _parent = best_path_tree(n, graph.out_steps(), base.step_dst, base.costs, origin)
            rows = []
            by_type: dict[str, int] = {}
            probability_of: dict[int, float] = {}
            for idx in range(1, n):
                if idx == origin:
                    continue
                lower = math.exp(-cost[idx]) if math.isfinite(cost[idx]) else 0.0
                high = max(float(upper[idx]), lower)
                value = min(max(float(est.probability[idx]), lower), high)
                if value <= 0.0:
                    continue
                probability_of[idx] = value
                if value < min_probability:
                    continue
                by_type[graph.types[idx]] = by_type.get(graph.types[idx], 0) + 1
                rows.append((value * max(float(graph.impact[idx]), 0.001), value, idx, lower, high))
            rows.sort(key=lambda r: (-r[0], -r[1], graph.ids[r[2]]))
            probability_of[origin] = 1.0
            services = self._service_impact(tenant_id, graph, viewer, probability_of, as_of)
            targets_hit = [r for r in rows if graph.impact[r[2]] > 0]
            return {
                "graph": self._meta(graph),
                "origin": self._node(graph, viewer, origin),
                "reachable": len(rows),
                "reachable_by_type": dict(sorted(by_type.items())),
                "targets_reachable": len(targets_hit),
                "expected_impact": _round(sum(r[1] * float(graph.impact[r[2]]) for r in targets_hit)),
                "nodes": [
                    {
                        **self._node(graph, viewer, idx),
                        "probability": {"lower": _round(lower), "estimate": _round(value), "upper": _round(high)},
                    }
                    for _score, value, idx, lower, high in rows[: max(1, min(limit, 500))]
                ],
                "business_services": services,
                "method": est.method,
            }

    def _service_impact(
        self,
        tenant_id: str,
        graph: AttackGraph,
        viewer: Viewer,
        probability_of: dict[int, float],
        as_of: datetime | None,
    ) -> list[dict[str, Any]]:
        """Business services that depend on any component the attacker may hold.

        A service is affected when a component it needs is compromised, so its
        probability is at least that of its most exposed component.
        """
        bindings = self.sem.bindings
        with self.db.snapshot() as session:
            reader = GraphReader(session, tenant_id)
            needs: dict[str, set[str]] = {}  # dependant -> things it needs
            supports = set(bindings.supports_edges)
            for _lineage, edge_type, src, dst, _props in reader.iter_edges(
                [*bindings.supports_edges, *bindings.depends_on_edges], as_of=as_of
            ):
                if edge_type in supports:  # component -> service
                    needs.setdefault(dst, set()).add(src)
                else:  # dependant -> dependency
                    needs.setdefault(src, set()).add(dst)
            affected: dict[str, tuple[float, str]] = {}

            def exposure(thing: str, seen: frozenset[str]) -> tuple[float, str] | None:
                idx = graph.index.get(thing)
                if idx is not None:
                    p = probability_of.get(idx, 0.0)
                    return (p, thing) if p > 0 else None
                best: tuple[float, str] | None = None
                for dependency in needs.get(thing, ()):
                    if dependency in seen:
                        continue
                    found = exposure(dependency, seen | {dependency})
                    if found is not None and (best is None or found[0] > best[0]):
                        best = found
                return best

            for dependant in needs:
                if dependant in graph.index:
                    continue  # a component, not a service
                found = exposure(dependant, frozenset({dependant}))
                if found is not None:
                    affected[dependant] = found
            records = reader.get_nodes(list(affected), as_of=as_of)
        out = []
        for service_id, (p, via) in affected.items():
            record = records.get(service_id)
            if record is None or not viewer.scope.allows(record.type):
                continue
            via_idx = graph.index[via]
            out.append(
                {
                    "id": service_id,
                    "type": record.type,
                    "name": record.name,
                    "criticality": record.properties.get("criticality"),
                    "regulatory_tags": record.properties.get("regulatory_tags", []),
                    "probability_at_least": _round(p),
                    "via": self._node(graph, viewer, via_idx),
                }
            )
        out.sort(key=lambda s: (-(s["criticality"] or 0) * s["probability_at_least"], s["name"]))
        return out

    def remediation_priorities(
        self,
        tenant_id: str,
        scope: AccessScope,
        *,
        by: str = "finding",
        limit: int = 20,
        time_budget_s: float = 10.0,
        as_of: datetime | None = None,
    ) -> dict[str, Any]:
        """Rank fixes by how much crown-jewel risk each one removes.

        For every candidate the attack graph is re-evaluated *as if that fix had
        been applied* and the drop in risk (Σ impact × compromise probability,
        noisy-OR bound) is reported. ``by`` chooses what one "fix" is:
        a single ``finding``, a ``vulnerability`` everywhere it occurs, or
        everything on one ``asset``.
        """
        if by not in ("finding", "vulnerability", "asset"):
            raise ValidationFailed("by must be finding, vulnerability or asset")
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="remediation_priorities"):
            viewer = Viewer(self.ontology, scope)
            base = self._baseline(graph)
            ex = graph.expand()
            risk_before = float(graph.impact @ base.upper)
            # Only findings on states that sit on some attacker → target route can matter.
            relevant_vertices = np.zeros(ex.vertices, dtype=bool)
            relevant_vertices[ex.dst[base.edge_index]] = True
            candidates: dict[str, dict[str, Any]] = {}
            for idx, exposures in graph.exposures.items():
                if not relevant_vertices[idx]:
                    continue
                reach = float(base.upper[idx]) if base.upper[idx] > 0 else 1.0
                for e in exposures:
                    if not e.remote or e.probability <= 0:
                        continue
                    if by == "finding":
                        key = e.finding_id
                    elif by == "vulnerability":
                        key = e.vulnerability_id or f"finding:{e.finding_id}"
                    else:
                        key = graph.ids[idx]
                    entry = candidates.setdefault(
                        key, {"findings": set(), "nodes": set(), "score": 0.0, "sample": e, "kev": False}
                    )
                    entry["findings"].add(e.finding_id)
                    entry["nodes"].add(idx)
                    entry["score"] += e.probability * reach * (1.0 + float(graph.impact[idx]))
                    entry["kev"] = entry["kev"] or e.kev
                    if e.probability > entry["sample"].probability:
                        entry["sample"] = e
            ordered = sorted(candidates.items(), key=lambda kv: (-kv[1]["score"], kv[0]))
            started = time.perf_counter()
            evaluated = []
            partial = False
            for key, entry in ordered:
                if time.perf_counter() - started > time_budget_s:
                    partial = True
                    break
                gates = graph.gate_probabilities(frozenset(entry["findings"]))
                p = ex.p.copy()
                used = ex.gate_position >= 0
                p[ex.gate_position[used]] = gates[used]
                risk_after, upper_after = self._upper_risk(graph, base, p)
                reduction = max(0.0, risk_before - risk_after)
                deltas = (base.upper - upper_after) * graph.impact
                top = [int(t) for t in np.argsort(-deltas)[:3] if deltas[t] > 1e-12]
                drops = [(t, float(base.upper[t] - upper_after[t])) for t in top]
                evaluated.append((reduction, key, entry, risk_after, drops))
            evaluated.sort(key=lambda r: (-r[0], r[1]))
            items = []
            for reduction, key, entry, risk_after, top_targets in evaluated[: max(1, min(limit, 200))]:
                sample = entry["sample"]
                nodes = sorted(entry["nodes"], key=lambda i: graph.ids[i])
                item: dict[str, Any] = {
                    "by": by,
                    "key": key,
                    "risk_reduction": _round(reduction),
                    "risk_reduction_percent": _round(100.0 * reduction / risk_before, 2) if risk_before > 0 else 0.0,
                    "risk_after": _round(risk_after),
                    "findings": len(entry["findings"]),
                    "known_exploited": entry["kev"],
                    "assets": [self._node(graph, viewer, i) for i in nodes[:5]],
                    "asset_count": len(nodes),
                    "protects": [
                        {**self._node(graph, viewer, t), "probability_drop": _round(drop)} for t, drop in top_targets
                    ],
                }
                if by == "finding":
                    item["finding"] = sample.as_dict()
                elif by == "vulnerability":
                    item["vulnerability"] = sample.vulnerability or sample.title
                    item["vulnerability_id"] = sample.vulnerability_id
                    item["highest_exploit_probability"] = _round(sample.probability)
                else:
                    item["highest_exploit_probability"] = _round(sample.probability)
                items.append(item)
            return {
                "graph": self._meta(graph),
                "by": by,
                "risk_before": _round(risk_before),
                "candidates": len(candidates),
                "evaluated": len(evaluated),
                "partial": partial,
                "items": items,
                "note": (
                    "risk = Σ over crown jewels of impact × compromise probability (noisy-OR upper bound). "
                    "Each item is scored by recomputing risk with that fix applied; reductions are not additive."
                ),
            }

    def choke_points(
        self, tenant_id: str, scope: AccessScope, *, limit: int = 10, as_of: datetime | None = None
    ) -> dict[str, Any]:
        """States whose hardening removes the most risk — where one control protects many crown jewels."""
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="choke_points"):
            viewer = Viewer(self.ontology, scope)
            base = self._baseline(graph)
            ex = graph.expand()
            risk_before = float(graph.impact @ base.upper)
            on_paths: dict[int, int] = {}
            ranked = sorted(
                (t for t in graph.targets if math.isfinite(base.lower_cost[t])),
                key=lambda t: -math.exp(-base.lower_cost[t]) * float(graph.impact[t]),
            )
            for target in ranked[:200]:
                path = self._path_from_tree(base, target)
                if path is None:
                    continue
                for node in path.nodes[1:-1]:
                    on_paths[node] = on_paths.get(node, 0) + 1
            results = []
            for node, paths_through in on_paths.items():
                p = ex.p.copy()
                p[(ex.src == node) | (ex.dst == node)] = 0.0
                risk_after, _upper = self._upper_risk(graph, base, p)
                reduction = max(0.0, risk_before - risk_after - float(graph.impact[node] * base.upper[node]))
                steps_in = [s for s in graph.in_steps()[node]]
                recommended: list[str] = []
                for step in steps_in:
                    rule = self._rules[graph.step_rule[step]]
                    have = {c.control_type for c in graph.step_controls[step]}
                    for control in rule.recommended_controls or rule.mitigated_by:
                        if control not in have and control not in recommended:
                            recommended.append(control)
                results.append(
                    {
                        **self._node(graph, viewer, node),
                        "risk_reduction": _round(reduction),
                        "risk_reduction_percent": _round(100.0 * reduction / risk_before, 2)
                        if risk_before > 0 else 0.0,
                        "best_paths_through": paths_through,
                        "compromise_probability_upper": _round(float(base.upper[node])),
                        "recommended_controls": recommended[:6],
                    }
                )
            results.sort(key=lambda r: (-r["risk_reduction"], r["id"]))
            return {
                "graph": self._meta(graph),
                "risk_before": _round(risk_before),
                "items": results[: max(1, min(limit, 100))],
                "note": "risk removed downstream if the attacker could never hold this state (its own impact excluded)",
            }

    def detection_race(
        self, tenant_id: str, scope: AccessScope, *, target_id: str | None = None, as_of: datetime | None = None
    ) -> dict[str, Any]:
        """Absorbing Markov chain: does the attacker reach a crown jewel before being detected?"""
        graph = self.graph(tenant_id, as_of=as_of)
        with timed(ANALYTICS_SECONDS, operation="detection_race"):
            viewer = Viewer(self.ontology, scope)
            base = self._baseline(graph)
            n = graph.state_count

            def solve(targets: list[int]) -> dict[str, Any]:
                result = absorbing_chain(
                    n, graph.step_src, graph.step_dst, graph.step_prob, graph.detection, ATTACKER_INDEX, targets
                )
                return {
                    "reach_before_detection": _round(result.reach_probability),
                    "detected_first": _round(result.detection_probability),
                    "contained": _round(result.contained_probability),
                    "expected_attempts": _round(result.expected_attempts, 3),
                    "states": result.states,
                    "solver": result.method,
                    "converged": result.converged,
                }

            if target_id is not None:
                target = self._index(graph, target_id, "target")
                return {
                    "graph": self._meta(graph),
                    "target": self._node(graph, viewer, target),
                    **solve([target]),
                }
            targets = graph.targets
            ranked = sorted(
                (t for t in targets if base.upper[t] > 0),
                key=lambda t: (-float(base.upper[t]) * float(graph.impact[t]), graph.ids[t]),
            )
            return {
                "graph": self._meta(graph),
                "any_target": solve(targets) if targets else None,
                "per_target": [{"target": self._node(graph, viewer, t), **solve([t])} for t in ranked[:10]],
                "note": (
                    "Persistent-attacker model: step probabilities are read as per-attempt success and failed "
                    "steps are retried, so harder steps take more attempts and give detection more chances. "
                    "Each attempt from a state is detected with that state's detection probability (detective "
                    "controls; a base rate otherwise). 'expected_attempts' counts attempts until the attack ends "
                    "by reaching a target, being detected, or running out of moves. This answers a different "
                    "question from compromise probability, which treats each step as possible-or-not."
                ),
            }

    def parameters(self) -> dict[str, Any]:
        """The model, in full: every rule and number the results depend on."""
        sem = self.sem
        return {
            "ontology": {"name": self.ontology.name, "version": self.ontology.version,
                         "fingerprint": self.ontology.fingerprint()},
            "attacker_states": list(sem.compromisable),
            "entries": [r.model_dump(mode="json") for r in sem.entries],
            "transitions": [r.model_dump(mode="json") for r in sem.transitions],
            "targets": [r.model_dump(mode="json") for r in sem.targets],
            "exploitability": sem.exploitability.model_dump(mode="json"),
            "controls": sem.controls.model_dump(mode="json"),
            "engine": {
                "monte_carlo_samples": self.settings.analytics_mc_samples,
                "seed": self.settings.analytics_seed,
                "cache_ttl_seconds": self.settings.analytics_cache_ttl_seconds,
            },
            "formulas": {
                "finding_exploitability": (
                    "p = min(max_probability, max(kev_floor if KEV, epss_weight·EPSS, "
                    "cvss_vector_weight·E(vector) or cvss_score_weight·score/10, unknown_default)) "
                    "× Π(1 − effectiveness of compensating controls on the finding or vulnerability)"
                ),
                "exploit_step": "max(floor, 1 − Π(1 − p_finding)) × Π(1 − effectiveness of mitigating controls)",
                "other_step": "base probability of the rule × Π(1 − effectiveness of mitigating controls)",
                "path": "product of step probabilities; paths ranked by probability × target impact",
                "compromise_lower": "probability of the most likely single path",
                "compromise_upper": "least fixed point of x_v = 1 − Π_{u→v}(1 − x_u·p_uv), x_attacker = 1",
                "compromise_estimate": "seeded Monte Carlo over independent step outcomes; exact enumeration "
                "when at most 14 uncertain steps are involved",
                "risk": "Σ over targets of impact × compromise probability",
                "detection_race": "absorbing Markov chain; see docs/ANALYTICS_MATH.md",
            },
        }

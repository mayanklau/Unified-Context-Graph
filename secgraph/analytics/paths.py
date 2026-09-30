"""Most probable attack paths (Dijkstra and Yen's K-shortest loop-free paths on ``-log p``)."""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass

import numpy as np

from secgraph.analytics.probability import best_path_tree


@dataclass(frozen=True)
class Path:
    steps: tuple[int, ...]  # step indices, attacker first
    nodes: tuple[int, ...]  # state indices, len(steps) + 1
    cost: float

    @property
    def probability(self) -> float:
        return math.exp(-self.cost)


def step_costs(probabilities: np.ndarray) -> list[float]:
    with np.errstate(divide="ignore"):
        return (-np.log(probabilities)).tolist()  # type: ignore[no-any-return]


def _trace(parent: list[int], edge_src: list[int], source: int, target: int) -> tuple[list[int], list[int]] | None:
    steps: list[int] = []
    nodes: list[int] = [target]
    cursor = target
    guard = len(parent) + 1
    while cursor != source:
        edge = parent[cursor]
        if edge < 0 or guard == 0:
            return None
        steps.append(edge)
        cursor = edge_src[edge]
        nodes.append(cursor)
        guard -= 1
    steps.reverse()
    nodes.reverse()
    return steps, nodes


def best_path(
    n: int,
    adjacency: list[list[int]],
    edge_src: list[int],
    edge_dst: list[int],
    costs: list[float],
    source: int,
    target: int,
    *,
    blocked_edges: frozenset[int] = frozenset(),
    blocked_nodes: frozenset[int] = frozenset(),
    allowed: np.ndarray | None = None,
) -> Path | None:
    cost, parent = best_path_tree(
        n, adjacency, edge_dst, costs, source,
        blocked_edges=blocked_edges, blocked_nodes=blocked_nodes, allowed=allowed, target=target,
    )
    if math.isinf(cost[target]):
        return None
    traced = _trace(parent, edge_src, source, target)
    if traced is None:
        return None
    steps, nodes = traced
    return Path(tuple(steps), tuple(nodes), cost[target])


def k_best_paths(
    n: int,
    adjacency: list[list[int]],
    edge_src: list[int],
    edge_dst: list[int],
    costs: list[float],
    source: int,
    target: int,
    k: int,
    *,
    allowed: np.ndarray | None = None,
    max_cost: float = math.inf,
) -> list[Path]:
    """Yen's algorithm: the ``k`` most probable loop-free paths from ``source`` to ``target``."""
    first = best_path(n, adjacency, edge_src, edge_dst, costs, source, target, allowed=allowed)
    if first is None or first.cost > max_cost:
        return []
    accepted: list[Path] = [first]
    candidates: list[tuple[float, tuple[int, ...], Path]] = []
    seen: set[tuple[int, ...]] = {first.steps}
    while len(accepted) < k:
        previous = accepted[-1]
        for i in range(len(previous.steps)):
            spur_node = previous.nodes[i]
            root_steps = previous.steps[:i]
            root_nodes = previous.nodes[: i + 1]
            blocked_edges = frozenset(
                path.steps[i] for path in accepted if len(path.steps) > i and path.nodes[: i + 1] == root_nodes
            )
            blocked_nodes = frozenset(root_nodes[:-1])
            spur = best_path(
                n, adjacency, edge_src, edge_dst, costs, spur_node, target,
                blocked_edges=blocked_edges, blocked_nodes=blocked_nodes, allowed=allowed,
            )
            if spur is None:
                continue
            steps = root_steps + spur.steps
            if steps in seen:
                continue
            total = sum(costs[s] for s in root_steps) + spur.cost
            if total > max_cost:
                continue
            seen.add(steps)
            path = Path(steps, root_nodes + spur.nodes[1:], total)
            heapq.heappush(candidates, (total, steps, path))
        if not candidates:
            break
        accepted.append(heapq.heappop(candidates)[2])
    return accepted

"""Compromise probability on a probabilistic attack graph.

Model: every attack step succeeds independently with its probability; a state
is compromised when the attacker can reach it through successful steps. The
probability that a state is compromised is then a network-reliability
quantity, which has no closed form on general graphs (it is #P-hard). We
therefore report three numbers, each with a precise meaning:

* ``lower``  — the probability of the single most likely path. Exact lower bound.
* ``upper``  — the noisy-OR fixed point ("Bayesian attack graph" propagation).
  A proven upper bound (see ``docs/ANALYTICS_MATH.md``), deterministic, fast.
* ``estimate`` — seeded Monte Carlo over step outcomes. Unbiased, reproducible
  (same seed → same number), reported with its standard error. For very small
  graphs the value is computed exactly by enumeration instead.

All three agree on tree-shaped graphs; they separate as paths share steps.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass

import numpy as np

EXACT_EDGE_LIMIT = 14


# --------------------------------------------------------------------------- #
# Pruning
# --------------------------------------------------------------------------- #
def forward_reachable(n: int, src: np.ndarray, dst: np.ndarray, p: np.ndarray, sources: list[int]) -> np.ndarray:
    """Boolean mask of vertices reachable from ``sources`` through edges with positive probability."""
    reach = np.zeros(n, dtype=bool)
    reach[sources] = True
    live = p > 0.0
    s, d = src[live], dst[live]
    while True:
        hit = reach[s] & ~reach[d]
        if not hit.any():
            return reach
        reach[d[hit]] = True


def backward_reachable(n: int, src: np.ndarray, dst: np.ndarray, p: np.ndarray, targets: list[int]) -> np.ndarray:
    return forward_reachable(n, dst, src, p, targets)


# --------------------------------------------------------------------------- #
# Upper bound: noisy-OR fixed point
# --------------------------------------------------------------------------- #
def noisy_or_bound(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    source: int = 0,
    *,
    tolerance: float = 1e-10,
    max_iterations: int = 1000,
) -> tuple[np.ndarray, int]:
    """Least fixed point of ``x_v = 1 - Π_{u→v} (1 - x_u · p_uv)`` with ``x_source = 1``.

    Iterating from zero is monotone, so the limit is the *least* fixed point,
    which bounds the true reachability probability from above.
    """
    x = np.zeros(n, dtype=np.float64)
    x[source] = 1.0
    if src.size == 0:
        return x, 0
    with np.errstate(divide="ignore"):
        for iteration in range(1, max_iterations + 1):
            contribution = np.minimum(x[src] * p, 1.0)
            log_miss = np.bincount(dst, weights=np.log1p(-contribution), minlength=n)
            updated = 1.0 - np.exp(log_miss)
            updated[source] = 1.0
            np.maximum(updated, x, out=updated)  # guard against rounding breaking monotonicity
            if float(np.max(updated - x)) < tolerance:
                return updated, iteration
            x = updated
    return x, max_iterations


# --------------------------------------------------------------------------- #
# Lower bound: most probable path
# --------------------------------------------------------------------------- #
def best_path_tree(
    n: int,
    adjacency: list[list[int]],
    edge_dst: list[int],
    edge_cost: list[float],
    source: int,
    *,
    blocked_edges: frozenset[int] = frozenset(),
    blocked_nodes: frozenset[int] = frozenset(),
    allowed: np.ndarray | None = None,
    target: int | None = None,
) -> tuple[list[float], list[int]]:
    """Dijkstra on costs ``-log p``. Returns ``(cost per vertex, incoming edge per vertex)``."""
    infinity = math.inf
    cost = [infinity] * n
    parent = [-1] * n
    cost[source] = 0.0
    heap: list[tuple[float, int]] = [(0.0, source)]
    done = [False] * n
    while heap:
        current_cost, u = heapq.heappop(heap)
        if done[u]:
            continue
        done[u] = True
        if u == target:
            break
        for edge in adjacency[u]:
            if edge in blocked_edges:
                continue
            v = edge_dst[edge]
            if done[v] or v in blocked_nodes or (allowed is not None and not allowed[v]):
                continue
            candidate = current_cost + edge_cost[edge]
            if candidate < cost[v]:
                cost[v] = candidate
                parent[v] = edge
                heapq.heappush(heap, (candidate, v))
    return cost, parent


# --------------------------------------------------------------------------- #
# Estimate: seeded Monte Carlo (and exact enumeration for tiny graphs)
# --------------------------------------------------------------------------- #
def _propagate(alive: np.ndarray, src: np.ndarray, order: np.ndarray, starts: np.ndarray, heads: np.ndarray,
               reached: np.ndarray) -> np.ndarray:
    """Close ``reached`` (worlds × vertices) under the alive edges of each world, in place."""
    src_sorted = src[order]
    alive_sorted = alive[:, order]
    while True:
        active = reached[:, src_sorted] & alive_sorted
        arrivals = np.logical_or.reduceat(active, starts, axis=1)
        fresh = arrivals & ~reached[:, heads]
        if not fresh.any():
            return reached
        reached[:, heads] |= arrivals


def _edge_groups(dst: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    order = np.argsort(dst, kind="stable")
    sorted_dst = dst[order]
    starts = np.flatnonzero(np.r_[True, sorted_dst[1:] != sorted_dst[:-1]])
    return order, starts, sorted_dst[starts]


@dataclass
class ReachEstimate:
    probability: np.ndarray  # per vertex
    stderr: np.ndarray  # per vertex; zero when exact
    samples: int
    method: str  # "exact" | "monte_carlo"


def exact_reach(n: int, src: np.ndarray, dst: np.ndarray, p: np.ndarray, source: int = 0) -> np.ndarray:
    """Exact reachability probabilities by enumerating every combination of step outcomes."""
    edges = int(src.size)
    if edges == 0:
        out = np.zeros(n)
        out[source] = 1.0
        return out
    worlds = 1 << edges
    bits = ((np.arange(worlds)[:, None] >> np.arange(edges)[None, :]) & 1).astype(bool)
    weights = np.prod(np.where(bits, p[None, :], 1.0 - p[None, :]), axis=1)
    order, starts, heads = _edge_groups(dst)
    reached = np.zeros((worlds, n), dtype=bool)
    reached[:, source] = True
    _propagate(bits, src, order, starts, heads, reached)
    return np.asarray(weights @ reached, dtype=np.float64)


def estimate_reach(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    source: int = 0,
    *,
    samples: int = 2000,
    seed: int = 0,
    budget: int = 40_000_000,
) -> ReachEstimate:
    """Probability that each vertex is reachable from ``source``.

    Only the part of the graph the source can reach is simulated. Certain
    steps (p = 1) and impossible steps (p = 0) consume no randomness.
    """
    probability = np.zeros(n, dtype=np.float64)
    stderr = np.zeros(n, dtype=np.float64)
    probability[source] = 1.0
    if src.size == 0:
        return ReachEstimate(probability, stderr, 0, "exact")

    relevant = forward_reachable(n, src, dst, p, [source])
    keep = relevant[src] & relevant[dst] & (p > 0.0) & (dst != source)
    sub_src, sub_dst, sub_p = src[keep], dst[keep], p[keep]
    if sub_src.size == 0:
        return ReachEstimate(probability, stderr, 0, "exact")
    vertices = np.flatnonzero(relevant)
    remap = np.full(n, -1, dtype=np.int64)
    remap[vertices] = np.arange(vertices.size)
    local_src, local_dst = remap[sub_src], remap[sub_dst]
    local_source = int(remap[source])
    local_n = int(vertices.size)

    uncertain = sub_p < 1.0
    uncertain_count = int(uncertain.sum())
    if uncertain_count <= EXACT_EDGE_LIMIT and (1 << uncertain_count) * int(sub_src.size) <= budget:
        # Enumerate only the uncertain steps; certain steps are always alive.
        certain_src, certain_dst = local_src[~uncertain], local_dst[~uncertain]
        u_src, u_dst, u_p = local_src[uncertain], local_dst[uncertain], sub_p[uncertain]
        count = int(u_src.size)
        worlds = 1 << count
        bits = ((np.arange(worlds)[:, None] >> np.arange(count)[None, :]) & 1).astype(bool)
        weights = np.prod(np.where(bits, u_p[None, :], 1.0 - u_p[None, :]), axis=1) if count else np.ones(1)
        all_src = np.concatenate([u_src, certain_src])
        all_dst = np.concatenate([u_dst, certain_dst])
        alive = np.concatenate([bits, np.ones((worlds, certain_src.size), dtype=bool)], axis=1)
        order, starts, heads = _edge_groups(all_dst)
        reached = np.zeros((worlds, local_n), dtype=bool)
        reached[:, local_source] = True
        _propagate(alive, all_src, order, starts, heads, reached)
        probability[vertices] = weights @ reached
        probability[source] = 1.0
        return ReachEstimate(probability, stderr, 0, "exact")

    rng = np.random.default_rng(seed)
    order, starts, heads = _edge_groups(local_dst)
    hits = np.zeros(local_n, dtype=np.int64)
    chunk = max(1, min(samples, budget // max(int(local_src.size), 1)))
    done = 0
    while done < samples:
        size = min(chunk, samples - done)
        alive = rng.random((size, local_src.size)) < sub_p[None, :]
        reached = np.zeros((size, local_n), dtype=bool)
        reached[:, local_source] = True
        _propagate(alive, local_src, order, starts, heads, reached)
        hits += reached.sum(axis=0)
        done += size
    mean = hits / float(samples)
    probability[vertices] = mean
    stderr[vertices] = np.sqrt(np.maximum(mean * (1.0 - mean), 0.0) / float(samples))
    probability[source] = 1.0
    stderr[source] = 0.0
    return ReachEstimate(probability, stderr, samples, "monte_carlo")

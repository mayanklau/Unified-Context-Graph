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


def noisy_or_update(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    base: np.ndarray,
    changed: np.ndarray,
    source: int = 0,
    *,
    tolerance: float = 1e-10,
    max_iterations: int = 1000,
) -> np.ndarray:
    """The noisy-OR bound after the probabilities of the edges ``changed`` were altered.

    ``base`` is the bound for the unaltered graph. Only vertices downstream of a changed
    edge can move; everything else keeps its value, because nothing upstream of the change
    depends on it. So the fixed point is recomputed on the downstream region alone, with
    the rest of the graph as a fixed boundary. The result equals a full recomputation.
    """
    if changed.size == 0:
        return base.copy()
    # A vertex's value depends only on its ancestors through edges that can still be taken,
    # so "downstream" follows the altered graph's positive edges from the heads of the changes.
    affected = np.zeros(n, dtype=bool)
    affected[dst[changed]] = True
    live = p > 0.0
    s, d = src[live], dst[live]
    while True:
        hit = affected[s] & ~affected[d]
        if not hit.any():
            break
        affected[d[hit]] = True
    affected[source] = False
    into = affected[dst]
    if int(into.sum()) > 0.6 * dst.size:  # most of the graph moves: the plain iteration is as cheap
        return noisy_or_bound(n, src, dst, p, source, tolerance=tolerance, max_iterations=max_iterations)[0]
    e_src, e_dst, e_p = src[into], dst[into], p[into]
    inner = affected[e_src]
    with np.errstate(divide="ignore"):
        # Contributions arriving from outside the region never change.
        fixed = np.bincount(
            e_dst[~inner], weights=np.log1p(-np.minimum(base[e_src[~inner]] * e_p[~inner], 1.0)), minlength=n
        )
        i_src, i_dst, i_p = e_src[inner], e_dst[inner], e_p[inner]
        x = np.where(affected, 0.0, base)
        for _ in range(max_iterations):
            log_miss = fixed + np.bincount(i_dst, weights=np.log1p(-np.minimum(x[i_src] * i_p, 1.0)), minlength=n)
            updated = np.where(affected, 1.0 - np.exp(log_miss), base)
            np.maximum(updated, x, out=updated)
            if float(np.max(updated - x)) < tolerance:
                return updated
            x = updated
    return x


def risk_sensitivity(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    x: np.ndarray,
    impact: np.ndarray,
    *,
    tolerance: float = 1e-9,
    max_iterations: int = 500,
) -> np.ndarray | None:
    """∂risk/∂p for every edge at once, where risk = Σ impact · x and ``x`` is the noisy-OR bound.

    One backward (adjoint) pass replaces one re-evaluation per edge: with
    ``g_e = (1 - x_v) / (1 - x_u·p_e)`` for an edge ``e = u→v``,

        ∂x_v/∂p_e = x_u · g_e          ∂x_v/∂x_u = p_e · g_e

    and the adjoint ``λ = impact + Jᵀλ`` is solved by iteration. Returns ``None`` when the
    iteration does not settle (a graph of certain steps in a loop), so callers can fall back.
    The result is a first-order estimate: it ranks candidate fixes, it does not score them.
    """
    if src.size == 0:
        return np.zeros(0, dtype=np.float64)
    denominator = 1.0 - x[src] * p
    with np.errstate(divide="ignore", invalid="ignore"):
        g = np.where(denominator > 1e-12, (1.0 - x[dst]) / denominator, 0.0)
    # States the attacker cannot reach contribute nothing, and loops among them must not be
    # allowed to feed the iteration.
    weight = np.where(x[src] > 0.0, p * g, 0.0)
    adjoint: np.ndarray = impact.astype(np.float64).copy()
    for _ in range(max_iterations):
        updated = impact + np.bincount(src, weights=weight * adjoint[dst], minlength=n)
        if not np.all(np.isfinite(updated)) or float(np.max(updated)) > 1e12:
            return None
        if float(np.max(np.abs(updated - adjoint))) <= tolerance * max(1.0, float(np.max(updated))):
            return np.asarray(adjoint[dst] * x[src] * g, dtype=np.float64)
        adjoint = updated
    return None


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
def _propagate(
    alive: np.ndarray, src: np.ndarray, order: np.ndarray, starts: np.ndarray, heads: np.ndarray, reached: np.ndarray
) -> np.ndarray:
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


def _simulate(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    source: int,
    samples: int,
    rng: np.random.Generator,
    budget: int,
) -> np.ndarray:
    """Count, per vertex, in how many of ``samples`` random worlds it is reachable from ``source``.

    Worlds are simulated 64 at a time: bit ``b`` of word ``w`` of a row is world ``64·w + b``.
    An edge row holds "alive in that world", a vertex row "reached in that world", so one
    sweep over the edges advances every world at once. ``budget`` bounds the number of
    (world, edge) pairs held in memory.
    """
    edges = int(src.size)
    order, starts, heads = _edge_groups(dst)
    src_sorted = src[order]
    p_sorted = p[order]
    uncertain = np.flatnonzero(p_sorted < 1.0)
    hits = np.zeros(n, dtype=np.int64)
    words_per_chunk = max(1, min((samples + 63) // 64, budget // (64 * max(edges, 1))))
    # Random draws are the largest temporary: a few worlds at a time, whole bytes of them.
    draw = max(8, min(64 * words_per_chunk, (budget // 8) // max(int(uncertain.size), 1)) // 8 * 8)
    done = 0
    while done < samples:
        size = min(64 * words_per_chunk, samples - done)
        words = (size + 63) // 64
        alive = np.full((edges, words * 8), 0xFF, dtype=np.uint8)
        if uncertain.size:
            packed = np.zeros((uncertain.size, words * 8), dtype=np.uint8)
            for offset in range(0, size, draw):
                count = min(draw, size - offset)
                outcome = rng.random((count, uncertain.size), dtype=np.float32) < p_sorted[uncertain][None, :]
                block = np.packbits(outcome, axis=0, bitorder="little")
                packed[:, offset // 8 : offset // 8 + block.shape[0]] = block.T
            alive[uncertain] = packed
        valid = np.packbits(np.arange(words * 64) < size, bitorder="little")  # worlds that exist in this chunk
        alive &= valid[None, :]
        alive_words = alive.view(np.uint64)
        reached = np.zeros((n, words), dtype=np.uint64)
        reached[source] = valid.view(np.uint64)
        while True:
            arrivals = np.bitwise_or.reduceat(reached[src_sorted] & alive_words, starts, axis=0)
            if not (arrivals & ~reached[heads]).any():
                break
            reached[heads] |= arrivals
        hits += np.bitwise_count(reached).sum(axis=1, dtype=np.int64)
        done += size
    return hits


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
    hits = _simulate(local_n, local_src, local_dst, sub_p, local_source, samples, rng, budget)
    mean = hits / float(samples)
    probability[vertices] = mean
    stderr[vertices] = np.sqrt(np.maximum(mean * (1.0 - mean), 0.0) / float(samples))
    probability[source] = 1.0
    stderr[source] = 0.0
    return ReachEstimate(probability, stderr, samples, "monte_carlo")

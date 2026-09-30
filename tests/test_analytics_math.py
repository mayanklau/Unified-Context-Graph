"""The mathematics, checked against brute force.

These tests do not touch the database: they verify the numerical core on
random graphs against exact enumeration, which is what makes the reported
bounds trustworthy.
"""

from __future__ import annotations

import itertools
import math
import random

import numpy as np
import pytest

from secgraph.analytics.markov import absorbing_chain
from secgraph.analytics.paths import k_best_paths, step_costs
from secgraph.analytics.probability import (
    best_path_tree,
    estimate_reach,
    exact_reach,
    noisy_or_bound,
    noisy_or_update,
    risk_sensitivity,
)


def random_graph(rng: random.Random, n: int, m: int, certain: float = 0.15):
    edges = {(0, 1)}  # the attacker always has at least one move
    m = min(m, (n - 1) ** 2)  # every ordered pair except self-loops and edges into the source
    while len(edges) < m:
        a, b = rng.randrange(n), rng.randrange(1, n)  # nothing points back at the source
        if a != b:
            edges.add((a, b))
    ordered = sorted(edges)
    src = np.array([e[0] for e in ordered], dtype=np.int64)
    dst = np.array([e[1] for e in ordered], dtype=np.int64)
    p = np.array([1.0 if rng.random() < certain else round(rng.uniform(0.05, 0.95), 3) for _ in ordered])
    return src, dst, p


def brute_force(n, src, dst, p):
    """Reference implementation: enumerate every world with plain Python."""
    out = [0.0] * n
    edges = list(zip(src.tolist(), dst.tolist(), p.tolist(), strict=True))
    for world in itertools.product((0, 1), repeat=len(edges)):
        weight = 1.0
        adjacency: dict[int, list[int]] = {}
        for alive, (a, b, prob) in zip(world, edges, strict=True):
            weight *= prob if alive else 1.0 - prob
            if alive:
                adjacency.setdefault(a, []).append(b)
        if weight == 0.0:
            continue
        seen, stack = {0}, [0]
        while stack:
            for nxt in adjacency.get(stack.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        for v in seen:
            out[v] += weight
    return np.array(out)


def best_path_probability(n, src, dst, p):
    adjacency = [[] for _ in range(n)]
    for e, a in enumerate(src.tolist()):
        adjacency[a].append(e)
    cost, _ = best_path_tree(n, adjacency, dst.tolist(), step_costs(p), 0)
    return np.array([math.exp(-c) if math.isfinite(c) else 0.0 for c in cost])


@pytest.mark.parametrize("seed", range(25))
def test_exact_enumeration_matches_reference_and_bounds_hold(seed):
    rng = random.Random(seed)
    n = rng.randint(4, 7)
    src, dst, p = random_graph(rng, n, rng.randint(4, 11))
    reference = brute_force(n, src, dst, p)
    exact = exact_reach(n, src, dst, p)
    assert np.allclose(exact, reference, atol=1e-12)

    lower = best_path_probability(n, src, dst, p)
    upper, _ = noisy_or_bound(n, src, dst, p)
    assert np.all(lower <= reference + 1e-9), "best single path must never exceed the true probability"
    assert np.all(reference <= upper + 1e-9), "noisy-OR fixed point must never fall below the true probability"

    estimate = estimate_reach(n, src, dst, p, samples=500, seed=1)
    assert estimate.method == "exact"  # tiny graphs are enumerated, not sampled
    assert np.allclose(estimate.probability, reference, atol=1e-12)


@pytest.mark.parametrize("seed", range(40))
def test_incremental_bound_equals_full_recomputation(seed):
    """What-if analysis recomputes only downstream of a change; it must match starting over."""
    rng = random.Random(7000 + seed)
    n = rng.randint(4, 60)
    src, dst, p = random_graph(rng, n, rng.randint(n, 4 * n))
    if seed % 3 == 0:  # some steps that are impossible today and become possible
        p[rng.sample(range(p.size), k=max(1, p.size // 6))] = 0.0
    base, _ = noisy_or_bound(n, src, dst, p)
    altered = p.copy()
    picks = rng.sample(range(p.size), k=rng.randint(1, max(1, p.size // 5)))
    for edge in picks:
        altered[edge] = rng.choice([0.0, 0.0, round(rng.uniform(0.01, 0.99), 3), 1.0])
    changed = np.flatnonzero(altered != p)
    expected, _ = noisy_or_bound(n, src, dst, altered)
    got = noisy_or_update(n, src, dst, altered, base, changed)
    assert np.allclose(got, expected, atol=1e-8), (seed, np.max(np.abs(got - expected)))
    assert got[0] == 1.0
    # nothing changed -> the base comes back untouched
    assert np.array_equal(noisy_or_update(n, src, dst, p, base, np.zeros(0, dtype=np.int64)), base)


def test_incremental_bound_on_a_long_chain_touches_only_the_tail():
    n = 2000
    src, dst = np.arange(n - 1), np.arange(1, n)
    p = np.full(n - 1, 0.999)
    base, _ = noisy_or_bound(n, src, dst, p, max_iterations=5000)
    altered = p.copy()
    altered[n - 10] = 0.5
    got = noisy_or_update(n, src, dst, altered, base, np.array([n - 10]), max_iterations=5000)
    expected, _ = noisy_or_bound(n, src, dst, altered, max_iterations=5000)
    assert np.allclose(got, expected, atol=1e-9)
    assert np.array_equal(got[: n - 9], base[: n - 9])  # upstream of the change is bit-for-bit the same


@pytest.mark.parametrize("seed", range(25))
def test_risk_sensitivity_matches_finite_differences(seed):
    rng = random.Random(9000 + seed)
    n = rng.randint(4, 30)
    src, dst, p = random_graph(rng, n, rng.randint(n, 3 * n), certain=0.0)
    p = np.clip(p, 0.05, 0.9)
    impact = np.array([0.0] + [rng.choice([0.0, 0.0, 4.0, 16.0]) for _ in range(n - 1)])
    impact[-1] = 8.0

    def risk(probabilities):
        return float(impact @ noisy_or_bound(n, src, dst, probabilities, tolerance=1e-14, max_iterations=20000)[0])

    x, _ = noisy_or_bound(n, src, dst, p, tolerance=1e-14, max_iterations=20000)
    gradient = risk_sensitivity(n, src, dst, p, x, impact, tolerance=1e-12, max_iterations=20000)
    assert gradient is not None and np.all(gradient >= -1e-12)  # a likelier step never lowers risk
    step = 1e-6
    for edge in rng.sample(range(p.size), k=min(8, p.size)):
        up, down = p.copy(), p.copy()
        up[edge] += step
        down[edge] -= step
        numeric = (risk(up) - risk(down)) / (2 * step)
        assert gradient[edge] == pytest.approx(numeric, rel=2e-3, abs=2e-4), (seed, edge)


def test_risk_sensitivity_gives_up_instead_of_returning_nonsense():
    # 0 -> 1 -> 2 -> 1 with certain steps: every state is certainly reached, nothing to differentiate
    src, dst, p = np.array([0, 1, 2]), np.array([1, 2, 1]), np.array([1.0, 1.0, 1.0])
    x, _ = noisy_or_bound(3, src, dst, p)
    gradient = risk_sensitivity(3, src, dst, p, x, np.array([0.0, 1.0, 1.0]))
    assert gradient is None or np.all(np.isfinite(gradient))
    assert (
        risk_sensitivity(1, np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.int64), np.zeros(0), x[:1], x[:1]).size
        == 0
    )


def test_bounds_coincide_on_a_tree():
    # attacker -> a -> b, attacker -> c : no shared steps, no reconvergence
    src = np.array([0, 1, 0])
    dst = np.array([1, 2, 3])
    p = np.array([0.5, 0.4, 0.3])
    exact = exact_reach(4, src, dst, p)
    upper, _ = noisy_or_bound(4, src, dst, p)
    lower = best_path_probability(4, src, dst, p)
    assert np.allclose(exact, [1.0, 0.5, 0.2, 0.3])
    assert np.allclose(upper, exact) and np.allclose(lower, exact)


def test_shared_step_is_not_double_counted_by_the_estimate():
    # attacker -(0.5)-> a, then two certain routes a->t. True P(t) = 0.5.
    src = np.array([0, 1, 1, 2])
    dst = np.array([1, 2, 3, 3])
    p = np.array([0.5, 1.0, 1.0, 1.0])
    exact = exact_reach(4, src, dst, p)
    upper, _ = noisy_or_bound(4, src, dst, p)
    assert exact[3] == pytest.approx(0.5)
    assert upper[3] == pytest.approx(0.75)  # the bound treats the two routes as independent: documented slack
    assert upper[3] >= exact[3]


def test_cycles_converge_and_stay_bounded():
    # a <-> b cycle fed by the attacker
    src = np.array([0, 1, 2, 2])
    dst = np.array([1, 2, 1, 3])
    p = np.array([0.3, 0.9, 0.9, 0.5])
    reference = brute_force(4, src, dst, p)
    upper, iterations = noisy_or_bound(4, src, dst, p)
    assert iterations < 1000
    assert np.all(upper <= 1.0) and np.all(reference <= upper + 1e-9)
    assert reference[1] == pytest.approx(0.3)  # the cycle cannot raise P(a) above its only entry
    assert upper[1] > 0.3  # ...but the bound lets the cycle reinforce itself


@pytest.mark.parametrize("seed", range(6))
def test_monte_carlo_is_reproducible_and_within_error_of_exact(seed, monkeypatch):
    import secgraph.analytics.probability as probability

    monkeypatch.setattr(probability, "EXACT_EDGE_LIMIT", -1)  # force sampling even on a graph small enough to enumerate
    rng = random.Random(100 + seed)
    n = 9
    src, dst, p = random_graph(rng, n, 18, certain=0.0)
    reference = brute_force(n, src, dst, p)
    first = estimate_reach(n, src, dst, p, samples=20000, seed=42)
    second = estimate_reach(n, src, dst, p, samples=20000, seed=42)
    assert first.method == "monte_carlo"
    assert np.array_equal(first.probability, second.probability), "same seed must give the same numbers"
    assert np.all(np.abs(first.probability - reference) <= 5 * first.stderr + 1e-3)
    other = estimate_reach(n, src, dst, p, samples=20000, seed=43)
    assert not np.array_equal(first.probability, other.probability)
    # chunking must not change the statistics
    chunked = estimate_reach(n, src, dst, p, samples=20000, seed=42, budget=18 * 1000)
    assert np.all(np.abs(chunked.probability - reference) <= 5 * chunked.stderr + 1e-3)


@pytest.mark.parametrize("samples", [1, 63, 64, 65, 1000, 4097])
def test_monte_carlo_counts_exactly_the_requested_worlds(samples, monkeypatch):
    """Worlds are packed 64 to a word; the padding in the last word must never count."""
    import secgraph.analytics.probability as probability

    monkeypatch.setattr(probability, "EXACT_EDGE_LIMIT", -1)
    # 0 -> 1 is certain, 1 -> 2 never happens, 0 -> 3 is a coin flip
    src, dst, p = np.array([0, 1, 0]), np.array([1, 2, 3]), np.array([1.0, 1e-12, 0.5])
    for budget in (1, 64 * 3, 40_000_000):
        result = estimate_reach(4, src, dst, p, samples=samples, seed=5, budget=budget)
        assert result.samples == samples and result.method == "monte_carlo"
        assert result.probability[0] == 1.0 and result.probability[1] == 1.0  # every world, no more
        assert result.probability[2] == 0.0
        assert 0.0 <= result.probability[3] <= 1.0
        assert round(result.probability[3] * samples, 9) == round(result.probability[3] * samples)  # a whole count


def test_estimate_ignores_unreachable_parts_and_handles_empty_graphs():
    empty = estimate_reach(3, np.array([], dtype=np.int64), np.array([], dtype=np.int64), np.array([]))
    assert empty.probability.tolist() == [1.0, 0.0, 0.0]
    src = np.array([1, 2])
    dst = np.array([2, 1])
    p = np.array([0.9, 0.9])  # island the attacker cannot reach
    island = estimate_reach(3, src, dst, p)
    assert island.probability.tolist() == [1.0, 0.0, 0.0]
    zero = estimate_reach(2, np.array([0]), np.array([1]), np.array([0.0]))
    assert zero.probability.tolist() == [1.0, 0.0]


# ---- K best paths -----------------------------------------------------------
def all_simple_paths(n, src, dst, p, target):
    adjacency: dict[int, list[tuple[int, int]]] = {}
    for e, (a, b) in enumerate(zip(src.tolist(), dst.tolist(), strict=True)):
        adjacency.setdefault(a, []).append((e, b))
    found = []

    def walk(node, visited, steps, prob):
        if node == target:
            found.append((prob, tuple(steps)))
            return
        for e, nxt in adjacency.get(node, ()):
            if nxt not in visited and p[e] > 0:
                walk(nxt, visited | {nxt}, [*steps, e], prob * float(p[e]))

    walk(0, {0}, [], 1.0)
    return sorted(found, key=lambda x: -x[0])


@pytest.mark.parametrize("seed", range(20))
def test_k_best_paths_match_exhaustive_enumeration(seed):
    rng = random.Random(500 + seed)
    n = rng.randint(5, 8)
    src, dst, p = random_graph(rng, n, rng.randint(7, 16), certain=0.0)
    target = n - 1
    adjacency = [[] for _ in range(n)]
    for e, a in enumerate(src.tolist()):
        adjacency[a].append(e)
    expected = all_simple_paths(n, src, dst, p, target)
    k = 5
    got = k_best_paths(n, adjacency, src.tolist(), dst.tolist(), step_costs(p), 0, target, k)
    assert len(got) == min(k, len(expected))
    assert [round(path.probability, 10) for path in got] == [round(prob, 10) for prob, _ in expected[:k]]
    for path in got:
        assert len(set(path.nodes)) == len(path.nodes), "paths must be loop-free"
        assert path.nodes[0] == 0 and path.nodes[-1] == target
        assert math.prod(float(p[s]) for s in path.steps) == pytest.approx(path.probability)
    assert len({path.steps for path in got}) == len(got)


# ---- Markov chain -----------------------------------------------------------
def simulate_chain(n, src, dst, p, detection, start, targets, runs, seed):
    rng = random.Random(seed)
    out: dict[int, list[tuple[int, float]]] = {}
    for a, b, prob in zip(src.tolist(), dst.tolist(), p.tolist(), strict=True):
        out.setdefault(a, []).append((b, prob))
    reached = detected = 0
    attempts_total = 0
    for _ in range(runs):
        state = start
        attempts = 0
        while True:
            if state in targets:
                reached += 1
                break
            moves = out.get(state)
            if not moves:
                break
            attempts += 1
            if rng.random() < detection[state]:
                detected += 1
                break
            total = sum(prob for _, prob in moves)
            pick = rng.random() * total
            for nxt, prob in moves:
                pick -= prob
                if pick <= 0:
                    if rng.random() < prob:
                        state = nxt
                    break
        attempts_total += attempts
    return reached / runs, detected / runs, attempts_total / runs


@pytest.mark.parametrize("seed", range(5))
def test_markov_chain_matches_simulation(seed):
    rng = random.Random(900 + seed)
    n = 8
    src, dst, p = random_graph(rng, n, 14, certain=0.1)
    detection = np.array([0.0] + [round(rng.uniform(0.02, 0.2), 3) for _ in range(n - 1)])
    targets = [n - 1]
    result = absorbing_chain(n, src, dst, p, detection, 0, targets)
    reach, detect, attempts = simulate_chain(n, src, dst, p, detection, 0, set(targets), 40000, seed)
    assert result.reach_probability == pytest.approx(reach, abs=0.012)
    assert result.detection_probability == pytest.approx(detect, abs=0.012)
    assert result.expected_attempts == pytest.approx(attempts, rel=0.05, abs=0.05)
    total = result.reach_probability + result.detection_probability + result.contained_probability
    assert total == pytest.approx(1.0, abs=1e-9)


def test_markov_hand_computed_single_step():
    # attacker -(p=0.5)-> target, detection 0.1 per attempt made from the attacker's state
    result = absorbing_chain(2, np.array([0]), np.array([1]), np.array([0.5]), np.array([0.1, 0.0]), 0, [1])
    den = 0.1 + 0.9 * 0.5
    assert result.reach_probability == pytest.approx(0.9 * 0.5 / den)
    assert result.detection_probability == pytest.approx(0.1 / den)
    assert result.expected_attempts == pytest.approx(1 / den)
    assert result.contained_probability == pytest.approx(0.0, abs=1e-12)


def test_markov_iterative_solver_agrees_with_dense(monkeypatch):
    import secgraph.analytics.markov as markov

    rng = random.Random(3)
    n = 30
    src, dst, p = random_graph(rng, n, 80, certain=0.1)
    detection = np.full(n, 0.05)
    detection[0] = 0.0
    dense = absorbing_chain(n, src, dst, p, detection, 0, [n - 1, n - 2])
    monkeypatch.setattr(markov, "DENSE_LIMIT", 0)
    iterative = absorbing_chain(n, src, dst, p, detection, 0, [n - 1, n - 2])
    assert dense.method == "dense" and iterative.method == "iterative" and iterative.converged
    assert iterative.reach_probability == pytest.approx(dense.reach_probability, abs=1e-7)
    assert iterative.detection_probability == pytest.approx(dense.detection_probability, abs=1e-7)
    assert iterative.expected_attempts == pytest.approx(dense.expected_attempts, rel=1e-6)


def test_markov_edge_cases():
    none = absorbing_chain(3, np.array([1]), np.array([2]), np.array([0.5]), np.zeros(3), 0, [2])
    assert none.reach_probability == 0.0 and none.contained_probability == 1.0
    already = absorbing_chain(2, np.array([0]), np.array([1]), np.array([0.5]), np.zeros(2), 0, [0])
    assert already.reach_probability == 1.0 and already.expected_attempts == 0.0

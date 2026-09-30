"""Absorbing Markov chain view of an attack.

Where ``probability.py`` asks "can the attacker get there at all", this model
asks "does the attacker get there *before being detected*, and how much effort
does it take". The attacker is a random walker on the attack graph:

* in state ``u`` the attacker picks one outgoing step, favouring likelier ones
  (weight ``w_uv = p_uv / Σ p_u·``);
* each attempt is detected with probability ``d_u`` (detective controls on
  ``u``; a small base rate otherwise) — detection ends the attack;
* otherwise the attempt succeeds with ``p_uv`` (the attacker moves) or fails
  (the attacker stays and tries again).

Targets, "detected" and dead ends are absorbing. With self-loops eliminated
the per-state quantities are

    s_u   = Σ_v w_uv · p_uv                 chance one attempt moves the attacker
    den_u = d_u + (1 - d_u) · s_u           chance one attempt changes anything
    q_uv  = (1 - d_u) · w_uv · p_uv / den_u chance the attacker eventually leaves to v
    n_u   = 1 / den_u                       expected attempts spent in u

and the answers solve two linear systems over the transient states:

    a = Q·a + r        a_u = P(reach a target before detection | start in u)
    t = Q·t + n        t_u = expected attempts until the attack ends
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from secgraph.analytics.probability import forward_reachable

DENSE_LIMIT = 1500


@dataclass
class MarkovResult:
    reach_probability: float  # P(attacker reaches a target before being detected)
    detection_probability: float  # P(attack is detected first)
    contained_probability: float  # P(attacker runs out of moves)
    expected_attempts: float  # expected number of attempts until the attack ends
    states: int
    method: str  # "dense" | "iterative"
    converged: bool


def absorbing_chain(
    n: int,
    src: np.ndarray,
    dst: np.ndarray,
    p: np.ndarray,
    detection: np.ndarray,
    start: int,
    targets: list[int],
    *,
    tolerance: float = 1e-10,
    max_iterations: int = 20000,
) -> MarkovResult:
    target_mask = np.zeros(n, dtype=bool)
    target_mask[targets] = True
    if target_mask[start]:
        return MarkovResult(1.0, 0.0, 0.0, 0.0, 1, "dense", True)

    live = (p > 0.0) & (src != dst)
    src, dst, p = src[live], dst[live], p[live]
    reach = forward_reachable(n, src, dst, p, [start])
    keep = reach[src] & ~target_mask[src]  # targets are absorbing: drop their outgoing steps
    src, dst, p = src[keep], dst[keep], p[keep]

    weight_sum = np.bincount(src, weights=p, minlength=n)
    move = np.bincount(src, weights=p * p, minlength=n)
    has_moves = weight_sum > 0.0
    s = np.divide(move, weight_sum, out=np.zeros(n), where=has_moves)
    d = np.clip(detection, 0.0, 1.0)
    den = d + (1.0 - d) * s
    transient = reach & has_moves & ~target_mask & (den > 0.0)
    if not transient[start]:
        return MarkovResult(0.0, 0.0, 1.0, 0.0, int(reach.sum()), "dense", True)

    # q_uv for every step leaving a transient state
    q = (1.0 - d[src]) * (p / weight_sum[src]) * p / den[src]
    visits = np.where(transient, 1.0 / np.where(den > 0.0, den, 1.0), 0.0)
    to_target = np.bincount(src, weights=np.where(target_mask[dst], q, 0.0), minlength=n)
    detected = np.where(transient, d / np.where(den > 0.0, den, 1.0), 0.0)
    inner = transient[dst]  # steps that stay among transient states
    i_src, i_dst, i_q = src[inner], dst[inner], q[inner]

    states = np.flatnonzero(transient)
    count = int(states.size)
    if count <= DENSE_LIMIT:
        local = np.full(n, -1, dtype=np.int64)
        local[states] = np.arange(count)
        matrix = np.eye(count)
        np.subtract.at(matrix, (local[i_src], local[i_dst]), i_q)
        rhs = np.stack([to_target[states], visits[states], detected[states]], axis=1)
        solution = np.linalg.solve(matrix, rhs)
        index = int(local[start])
        reach_p, attempts, detect_p = (float(solution[index, c]) for c in range(3))
        method, converged = "dense", True
    else:
        a: np.ndarray = np.zeros(n)
        t: np.ndarray = np.zeros(n)
        k: np.ndarray = np.zeros(n)
        converged = False
        for _ in range(max_iterations):
            a_new = to_target + np.bincount(i_src, weights=i_q * a[i_dst], minlength=n)
            t_new = visits + np.bincount(i_src, weights=i_q * t[i_dst], minlength=n)
            k_new = detected + np.bincount(i_src, weights=i_q * k[i_dst], minlength=n)
            delta = max(
                float(np.max(np.abs(a_new - a))),
                float(np.max(np.abs(k_new - k))),
                float(np.max(np.abs(t_new - t)) / max(1.0, float(np.max(t_new)))),
            )
            a, t, k = a_new, t_new, k_new
            if delta < tolerance:
                converged = True
                break
        reach_p, attempts, detect_p = float(a[start]), float(t[start]), float(k[start])
        method = "iterative"
    reach_p = min(1.0, max(0.0, reach_p))
    detect_p = min(1.0, max(0.0, detect_p))
    contained = min(1.0, max(0.0, 1.0 - reach_p - detect_p))
    return MarkovResult(reach_p, detect_p, contained, max(0.0, attempts), count, method, converged)

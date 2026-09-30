# The maths behind the numbers

Every analytic in the Security Graph is a deterministic function of the stored graph and the
ontology file. This document states each formula, proves the two bounds, and says exactly what each
reported number means and does not mean. The implementation is in `secgraph/analytics/`; the tests
that check it against brute force are in `tests/test_analytics_math.py`.

All parameters named here live in `attack_semantics` in the ontology file and are returned by
`GET /api/v1/analytics/parameters`. **They are priors.** They encode a defensible starting position
and are meant to be calibrated against the organisation's own incident and red-team history.

## 1. From graph to attack graph

The ontology says which relationships let an attacker move:

- **Entry rules** — where an outside attacker can start (an internet-exposed asset; the internet
  segment).
- **Transition rules** — a relationship type, the direction the attacker moves along it, a
  predicate on its properties, and a probability model.
- **Target rules** — what counts as a crown jewel and its impact weight.

Applying these to the stored graph gives the attack graph: **states** (things an attacker can hold,
plus a virtual `attacker` state) and **steps** (one movement, with a success probability). The
shipped rules are listed in [ONTOLOGY.md](ONTOLOGY.md).

### Step probability

Each step's probability comes from one of three models:

| Model | Probability |
|---|---|
| `fixed` | a constant from the rule |
| `by_property` | looked up from a property of the relationship (for example `privilege: admin → 0.95`) |
| `exploitability` | how likely the *destination* can be exploited — below |

Controls recorded as protecting the relevant end of a step, of a type the rule lists under
`mitigated_by`, multiply the probability by `(1 − effectiveness)` each, floored so that controls
never remove more than `max_combined_reduction` (0.99):

```
p_step = p_model × max( Π (1 − eff_c), 1 − max_combined_reduction )
```

A control's effectiveness is its recorded `effectiveness`, or the default for its type; halved
(`degraded_factor`) when its status is degraded; zero when it is inactive or planned.

### Exploitability of a finding

For one open finding, with the vulnerability it is an instance of:

```
p = min( max_probability,
         max( kev_floor                    if the vulnerability is in the KEV catalogue   (0.90)
              epss_weight × EPSS                                                          (1.0)
              cvss_vector_weight × E(vector)   if a CVSS vector is present                (0.6)
              cvss_score_weight × score / 10   otherwise, if a base score is present      (0.3)
              unknown_default ) )                                                         (0.05)
```

`E(vector)` is the CVSS exploitability sub-score scaled to [0, 1]. A finding with no linked
vulnerability (a misconfiguration) is scored from its severity. Compensating controls recorded
against the finding or the vulnerability multiply the result by `(1 − effectiveness)`. The response
names the term that won (`basis`: `kev`, `epss`, `cvss_vector`, `cvss_score`, `severity`,
`default`), so a reader can see why a finding scored as it did.

Only findings whose status is in `open_statuses` count. A risk-accepted finding still counts —
accepting a risk does not remove it — and is flagged.

### Exploitability of a target, and gates

A target with several open, remotely exploitable findings is exploitable if any one is:

```
p_target = 1 − Π_f (1 − p_f)        (floored at the rule's `floor`, if it has one)
```

If fifty neighbours can each attack the same host, that is **not** fifty independent chances: the
host is either exploitable or it is not. So every exploit step into one target shares a single
random event, a **gate**. Internally the attack graph is expanded: a gated step `u → v` becomes
`u → gate_v` (carrying the route's own control factor) and one shared edge `gate_v → v` (carrying
`p_target`). After expansion every edge is an independent event, which is what the results below
assume.

## 2. Compromise probability: two bounds and an estimate

**Model.** Each edge of the expanded attack graph is *alive* independently with its probability. A
state is compromised if it is reachable from the attacker through alive edges. Write `P(v)` for the
probability that `v` is compromised.

`P(v)` is a two-terminal network reliability, which has no closed form on general graphs (computing
it exactly is #P-hard). Rather than report one number of unknown quality, every response gives
three, each with a precise status:

```json
{"lower": 0.399, "upper": 0.638, "estimate": 0.631, "stderr": 0.0, "method": "exact"}
```

### Lower bound — the most probable path

```
lower(v) = max over attacker→v paths π of  Π_{e ∈ π} p_e
```

computed by Dijkstra on edge costs `−log p_e`.

*Proof that it is a lower bound.* If every edge of `π` is alive, `v` is reachable. Those edges are
independent, so that event has probability `Π p_e`, and `P(v)` is at least that. ∎

This is the number shown as a path's probability. It is the chance that *this particular route*
works, which is why it is lower than the chance that *some* route works.

### Upper bound — the noisy-OR fixed point

```
x_attacker = 1
x_v        = 1 − Π_{u→v} (1 − x_u · p_uv)
```

iterated from zero until it stops changing. This is the propagation rule of a Bayesian attack
graph. On a tree it is exact; where routes share steps it double-counts them, and the claim is that
it can only err upwards.

*Theorem.* Let `x*` be the limit of the iteration started at zero. Then `P(v) ≤ x*_v` for every `v`.

*Proof.* Let `R_v^k` be the event that `v` is reachable through alive edges by a path of at most
`k` edges, and let `x^k` be the `k`-th iterate. We show `P(R_v^k) ≤ x_v^k` by induction on `k`;
`k = 0` is immediate.

`v` is reached within `k` edges exactly when, for some in-neighbour `u`, `u` is reached within
`k − 1` edges and the edge `u→v` is alive. So

```
¬R_v^k = ⋂_u A_u,      A_u = ¬R_u^{k−1} ∪ {u→v is dead}.
```

Each `A_u` is a *decreasing* event: if it holds for some set of alive edges, it still holds when
edges are removed. Edges are independent, so by the Harris (FKG) inequality decreasing events are
positively correlated:

```
P(⋂_u A_u) ≥ Π_u P(A_u).
```

Next, `R_u^{k−1}` does not depend on the edge `u→v`: a path that reaches `u` and uses `u→v` must
have visited `u` before using it, so cutting the path at that first visit gives a shorter path to
`u` that does not use `u→v`. Hence `R_u^{k−1}` and `{u→v alive}` are independent and
`P(A_u) = 1 − P(R_u^{k−1}) · p_uv`. Putting it together with the induction hypothesis,

```
P(R_v^k) = 1 − P(⋂_u A_u) ≤ 1 − Π_u (1 − P(R_u^{k−1}) p_uv) ≤ 1 − Π_u (1 − x_u^{k−1} p_uv) = x_v^k.
```

The iteration is monotone (each `x^k ≥ x^{k−1}`), so it converges to `x*`; and `R_v^k` increases to
"`v` is reachable". Taking limits gives `P(v) ≤ x*_v`. ∎

Starting from zero matters: on a graph with cycles the equations can have more than one solution,
and the iteration from zero finds the smallest, which is the tightest bound of this form.

### Estimate — seeded Monte Carlo, or exact enumeration

The estimate samples worlds: draw every uncertain edge alive or dead, find what is reachable,
repeat `SECGRAPH_ANALYTICS_MC_SAMPLES` times (2,000 by default), and report the fraction of worlds
in which each state was reached, with its standard error `√(p(1−p)/N)`.

- The estimator is unbiased for `P(v)`. With 2,000 samples the standard error is at most 0.011.
- It is **seeded** (`SECGRAPH_ANALYTICS_SEED`): the same graph state and settings give the same
  number on every call and every replica. It is recomputed only when the graph changes.
- Only the part of the graph on some attacker → crown-jewel route is simulated.
- When that part has at most 14 uncertain edges, every combination is enumerated instead and the
  result is exact (`"method": "exact"`, `stderr` 0).
- Worlds are simulated 64 at a time with bitwise operations, which is what makes 2,000 worlds over
  tens of thousands of steps take about a second.

The tests enumerate every world of random graphs by brute force and check
`lower ≤ exact ≤ upper`, that the enumerated estimate equals the brute-force value, and that the
sampled estimate is within five standard errors of it.

### Reading the three numbers

- The bounds are **proven** statements about the model. If `upper` is 2%, then under the model's
  assumptions the chance is at most 2%, whatever the estimate says.
- A wide gap between `lower` and `upper` means many routes share steps. The estimate tells you
  where in the gap the truth lies.
- None of the three is a prediction of breach likelihood in a calendar period. They answer: *given
  an attacker who tries, and given these exploit and control probabilities, how likely is it that a
  route exists?* Use them to rank and to compare before and after a change.

### Risk

```
risk = Σ over crown jewels t of  impact_t × P(t)
```

reported as a lower bound, an upper bound and an estimate, using the corresponding probability.
Impact weights come from the target rules (by default 1, 2, 4, 8, 16 for criticality 1–5).

## 3. Attack paths

`GET /analytics/attack-paths` returns, for a target, the `K` most probable loop-free paths (Yen's
algorithm on `−log p` costs), and for the estate as a whole the single best path to each crown
jewel ranked by `probability × impact`. Every step carries the rule that produced it, the findings
behind an exploit step with their evidence, the controls that were applied, and the controls the
rule recommends that are absent. The tests compare Yen's output with exhaustive enumeration.

## 4. What to fix first

For a candidate fix — one finding, one vulnerability everywhere it occurs, or everything on one
asset — the attack graph is re-evaluated as if the fix were applied, and the fall in risk under the
upper bound is reported:

```
risk_removed(fix) = risk_upper(graph) − risk_upper(graph with those findings closed)
```

This is a what-if on the whole graph, so it accounts for alternative routes: closing a finding that
the attacker can simply walk around removes little. Reductions are **not additive** — two fixes on
the same route each remove most of it.

Two things keep this fast and honest on a large estate:

- **The recomputation is incremental and exact.** Only states downstream of the changed steps can
  change, so the fixed point is recomputed there with the rest of the graph as a boundary. The
  tests check it equals a full recomputation.
- **Candidates are ranked before they are scored.** One backward (adjoint) pass gives `∂risk/∂p`
  for every step at once; each candidate gets a first-order estimate of the risk it removes, and
  the exact recomputation then works down that list within a time budget (10 s by default,
  `time_budget_s` up to 60). On a synthetic 10,000-asset estate the first-order ranking and the
  exact ranking had a rank correlation of 0.999. If the budget ends before every candidate is
  scored, the response says so (`"partial": true`, with `evaluated` and `candidates`), and the
  result is kept until the graph changes.

The adjoint: with `g_e = (1 − x_v) / (1 − x_u p_e)` for an edge `e = u→v`,

```
∂x_v/∂p_e = x_u · g_e        ∂x_v/∂x_u = p_e · g_e        λ = impact + Jᵀλ        ∂risk/∂p_e = λ_v · x_u · g_e
```

checked against finite differences in the tests.

**Choke points** are states on the most probable paths, scored by the risk removed downstream if
the attacker could never hold that state (the state's own impact excluded). They answer "where does
one control protect the most?".

## 5. Blast radius

`GET /analytics/nodes/{id}/blast-radius` assumes the node is already compromised: the outside
attacker's entry steps are replaced by a certain foothold there, and the same three numbers are
computed for everything reachable. Business services are then listed with the probability of the
most exposed component they depend on (`SUPPORTS`, `DEPENDS_ON`, followed transitively) and which
component that is. A service is affected when any component it needs is compromised, so this is a
lower bound on the chance the service is affected — and it names the component to look at.

## 6. The detection race

Compromise probability asks whether a route *exists*. The detection race asks a different question:
does a persistent attacker get there **before being detected**, and how much effort does it take?
It is an absorbing Markov chain on the attack graph:

- in state `u` the attacker picks an outgoing step with weight `w_uv = p_uv / Σ p_u·`;
- each attempt is detected with probability `d_u` — from detective controls (EDR, NDR, SIEM
  detections, deception) protecting `u`, combined as `1 − (1 − detection_base) Π (1 − detection_weight × eff_c)`;
- otherwise the attempt succeeds with `p_uv` and the attacker moves, or fails and the attacker
  tries again.

With `s_u = Σ_v w_uv p_uv` and `den_u = d_u + (1 − d_u) s_u`, the chance of eventually leaving `u`
to `v` is `q_uv = (1 − d_u) w_uv p_uv / den_u`, and the expected number of attempts spent in `u` is
`1 / den_u`. Two linear systems over the transient states give the answers:

```
a = Q a + r      a_u = P(reach a crown jewel before detection | at u)
t = Q t + n      t_u = expected attempts until the attack ends
```

solved directly up to 1,500 states and iteratively above that. The result is three probabilities
that sum to one — attacker wins, detected first, contained (runs out of moves) — and the expected
number of attempts. The tests compare it with direct simulation.

**Do not compare this number with compromise probability.** Here a step's probability is read as
*per-attempt success* and failed steps are retried, so a persistent attacker eventually gets
through any step that is possible at all; what stops them is detection. There, a step is either
possible or not. They are two models answering two questions, and the response says which one it
is.

## 7. Assumptions, stated plainly

- **Independence.** Steps succeed independently (after gates remove the most obvious dependence).
  Real attackers reuse one exploit across many hosts and one stolen credential across many systems;
  to that extent the model understates correlation.
- **Monotonicity.** Gaining a position never makes another step harder.
- **The graph is the evidence.** A route the graph does not contain — an unrecorded connection, an
  unknown credential — has probability zero. The numbers are only as complete as the data.
- **A static snapshot.** No time dimension within one computation: no attacker dwell time, no
  patch lead time. Use `as_of` to compare two moments.
- **Priors.** KEV → 0.9, the EPSS and CVSS weights, the default control effectiveness values and
  the detection parameters are judgement, written down. Calibrate them.

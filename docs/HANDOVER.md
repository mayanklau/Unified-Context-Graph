# Handover

For the team taking this over. It says what you have, what has been verified and how, what has not,
and what to decide before production. Nothing here needs the original authors.

## Start here

```bash
git clone <this repository> && cd security-graph
./scripts/quickstart.sh --demo        # Docker: PostgreSQL + API + worker, demo estate, admin password printed
# or, with no Docker:
make demo                             # SQLite, demo estate, admin / Meridian-Demo-2026
```

Open `http://127.0.0.1:8080`. Then, in this order:

1. **Overview** and **Attack paths** in the console — what the product is for, in two screens.
2. [README.md](../README.md) — the five-minute tour of the API.
3. [ARCHITECTURE.md](ARCHITECTURE.md) — how it is built.
4. [CLAUDE.md](../CLAUDE.md) — where everything lives and the rules that are easy to break. It is
   written for coding agents and is the fastest map for people too.
5. `make check` — the whole test suite, a couple of minutes.

## What you have

| | |
|---|---|
| Code | ~15,000 lines of Python in `secgraph/`, ~1,600 lines of dependency-free JavaScript/CSS for the console |
| Tests | 383, in ~5,000 lines: unit, integration through the real API, browser tests of the console, concurrency tests on PostgreSQL, maths checked against brute force |
| Runtime dependencies | 12 direct, 37 in total, pinned with hashes |
| Stateful dependencies | PostgreSQL. Nothing else. |
| Interfaces | REST (50 paths), MCP (18 tools), console, CLI (14 commands), Python client, change feed, webhooks, Markdown vault |
| Packaging | container image, Docker Compose (+ TLS overlay), Kubernetes manifests, air-gap bundle, systemd notes |

## What has been verified, and how

Everything in this table was run, not assumed.

| Claim | Evidence |
|---|---|
| The test suite passes | 383 tests on SQLite and the same suite on PostgreSQL 16 (Python 3.11); on Python 3.12 from a fresh clone installed from the hashed lock file (SQLite) |
| Lint and types are clean | `ruff check`, `ruff format --check`, `mypy` (untyped definitions disallowed) |
| Coverage | 93% of statements on the SQLite run |
| The bounds are bounds | lower ≤ exact ≤ upper against brute-force enumeration on random graphs; proofs in [ANALYTICS_MATH.md](ANALYTICS_MATH.md) |
| The estimate is unbiased and reproducible | within five standard errors of the exact value; identical for the same seed; padding in the bit-packed simulation never counted |
| What-if results are exact | the incremental recomputation equals a full one on 40 random graphs; sensitivities equal finite differences on 25 |
| K-best paths, Markov chain | equal exhaustive enumeration; equal direct simulation |
| Concurrent ingestion is safe | parallel overlapping loads on PostgreSQL: no lost updates, no duplicate entities, gap-free change and audit sequences |
| Migrations match the models | a test compares the migrated schema with the ORM metadata |
| The console works and is safe against injected markup | Chromium: every section, role-based navigation, both sign-in paths, narrow screens in light and dark, an HTML payload in an asset name stays inert; no console errors, no CSP violations |
| MCP interoperates | the official MCP Python SDK client lists and calls the tools over HTTP |
| Harness connectors fit | `isinstance` checks against the Agentic SOC Harness's connector protocols |
| The image builds offline and runs locked down | `docker build --network none` from a wheelhouse; runs as uid 10001, read-only root filesystem, no capabilities |
| The Docker quickstart works from nothing | `scripts/quickstart.sh --demo`: healthy stack with demo data in under a minute; running it again changes nothing |
| The TLS overlay works | HTTPS and HTTP/2 through nginx with a test certificate; the API no longer published directly |
| The air-gap bundle installs | built, unpacked, checksums verified, images removed from the host, `install.sh --demo` brought the stack up from the bundle alone |
| Kubernetes manifests are well-formed | `kubeconform -strict` against the Kubernetes 1.30 schemas: 14 resources valid |
| Performance | measured; see [OPERATIONS.md](OPERATIONS.md#sizing) |

## What has not been verified

Be clear-eyed about these.

- **The Kubernetes manifests have never been applied to a cluster.** They are schema-valid and the
  image they run is tested under the same security context in Compose. Expect to adjust ingress
  class, NetworkPolicy namespace labels and resource requests. Do a dry run in a non-production
  namespace first.
- **The CI workflow has not run.** `.github/workflows/ci.yml` mirrors commands that were run by
  hand; its first run on GitHub may need small fixes (action versions, runner differences).
- **No real source data has been loaded.** The ten mappings are tested against realistic samples
  written from the formats' specifications, not against an export from the bank's actual CMDB,
  scanner or SIEM. The first real file from each source will likely need mapping adjustments — that
  is what quarantine reasons are for.
- **No estate larger than 50,000 assets has been measured**, and all measurements were on a
  two-core machine with the database on the same host.
- **No penetration test and no independent code or security review.** The authors found and fixed
  issues while testing and documenting (see the commit history); nobody else has looked yet.
- **The integrations with CRVM, Remediation OS, the asset inventory and AgentPEP / Thoth are
  contracts, not working adapters** — except the Agentic SOC Harness connectors, which exist and
  are tested against its protocol definitions. [INTEGRATION.md](INTEGRATION.md) says what each
  product has to do.
- **The probabilities are uncalibrated priors.** The maths is checked; the inputs (KEV → 0.9, EPSS
  and CVSS weights, default control effectiveness, detection rates) are documented judgement.
- **MCP protocol 2026-07-28 is not implemented.** The server speaks 2025-06-18 and earlier;
  current SDK clients negotiate down to that, which is tested.

## Decisions for you

| Decision | Default today | Why it is yours |
|---|---|---|
| **Licence** | Apache-2.0, matching `agentic-soc-harness` | `security-context-graph` is marked proprietary. Pick one deliberately: change `LICENSE` and `pyproject.toml`. |
| **Calibration** | shipped priors | Compare the model's step probabilities with red-team results and incident history, then edit `attack_semantics` in a copy of the ontology. Until then, use the numbers to rank, not as likelihoods. |
| **Which source outranks which** | none set | `SECGRAPH_SOURCE_PRIORITY`. Usually the CMDB for ownership and criticality, the EDR for what is running. |
| **Who may see personal data** | `analyst`, `steward`, `admin` | Roles are in `secgraph/governance/rbac.py`. Agents do not see it. |
| **Sign-in for people** | local accounts | Put the console behind SSO, or issue tokens from the identity provider ([OPERATIONS.md](OPERATIONS.md)). Local accounts have no MFA. |
| **History retention** | keep everything | `SECGRAPH_HISTORY_RETENTION_DAYS`. Growth follows change volume. |
| **Phishing as an entry point** | off | The `phishing` entry rule is in the ontology, disabled. Turning it on makes every human identity a possible start. |
| **Tenancy** | one tenant, `default` | The model is multi-tenant throughout. Decide whether business units or environments are tenants before loading data; merging tenants later is a migration. |

## First week, suggested

1. Run the quickstart; walk the console with the demo estate.
2. Load one real asset export and one real scanner export into a scratch tenant
   (`--tenant trial`). Read the quarantine reasons and the identity conflicts; adjust mappings.
3. Load NVD, KEV and EPSS files. Mark crown jewels (`crown_jewel`, `criticality`) and
   internet-exposed assets — without those two, there are no attack paths to compute.
4. Add network reachability (`IN_SEGMENT`, `ROUTES_TO`, `CONNECTS_TO`) and access
   (`HAS_ACCESS`, `HAS_SESSION`, `MEMBER_OF`). The attack graph is only as complete as these.
5. Show **Fix first** to the CRVM owners and ask whether the order matches their judgement. Where
   it does not, find out whether the data or the weights are wrong. That conversation is the
   calibration.
6. Give one agent an `agent` key and point it at `/mcp`.
7. Let CI run; fix whatever its first run turns up.
8. Dry-run the Kubernetes manifests.

## Known limitations

Collected from the other documents so they are in one place.

- Rate limits and the attack-graph cache are per API replica.
- After a load, analytics may lag by up to five minutes (`SECGRAPH_ANALYTICS_CACHE_TTL_SECONDS`);
  every response says which graph state it used.
- An `as_of` analytics request rebuilds the attack graph each time; it is not cached.
- History is system time — what the graph knew when — not a bitemporal model of when facts were
  true in the world. Records carry `first_seen` and `last_seen` from their sources.
- Ingestion is around 1,500–2,300 records per second per process on PostgreSQL on a two-core
  machine. It is safe to run several loads in parallel.
- Remediation priorities and choke points work within a time budget and say when they were cut
  short (`partial`).
- Identifier search is by substring on names and exact match on identifiers; there is no fuzzy or
  full-text search.
- The console has no graph editing; data changes go through ingestion and curation.
- Webhook signing secrets are stored in the database in clear; local session tokens cannot be
  revoked individually; the protective-plane hook covers context packs and memory writes, not
  every read. See [SECURITY.md](SECURITY.md).
- `/docs` and `/redoc` need a CDN and should be off on an air-gapped network; `/openapi.json` and
  `docs/openapi.json` do not.

## If something is wrong

`secgraph doctor` first. Then [OPERATIONS.md](OPERATIONS.md#troubleshooting). Every error response
and every log line carries a `request_id`; start from that.

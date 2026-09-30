# Security Graph — map for coding agents

Read this first. It is the index: what the project is, where things live, how to check your work,
and the rules that are easy to break without noticing. Follow the links for depth; do not guess.

## What this is

A sovereign, on-prem security graph: one ontology-driven graph of assets, identities, exposure,
controls, detections and AI agents, stored in PostgreSQL, with deterministic attack-path analytics
and a governed interface (REST, MCP, context packs, shared memory) for the agents that use it.
Python 3.11+, FastAPI, SQLAlchemy 2, numpy. No network access at run time. No other services.

## Commands

```bash
make install     # once
make check       # ruff + mypy + pytest (SQLite). Run before you say you are done.
make test-postgres SECGRAPH_TEST_DATABASE_URL=postgresql+psycopg://…   # same suite on PostgreSQL
make test-ui     # console in a real browser (needs Chromium)
make docs        # regenerate docs/ONTOLOGY.md and docs/openapi.json — required after ontology or route changes
make demo        # run it locally with the demonstration estate
.venv/bin/python -m pytest tests/test_ingest.py -x -q -k conflict   # one area
```

## Where things are

| You want to change… | Go to | Then |
|---|---|---|
| an entity type, property, identifier, relationship, attack rule or weight | `secgraph/ontology/core.ontology.yaml` | `make docs`; tests in `tests/test_ontology.py` |
| how a source format is read | `secgraph/ingest/mappings/*.yaml` | sample in `secgraph/demo/sources/`, test in `tests/test_mappings.py` |
| validation, identity resolution, versioned upsert | `secgraph/ingest/service.py` | `tests/test_ingest.py`, `tests/test_concurrency.py` |
| merge, conflicts, quarantine, expiry, retention | `secgraph/ingest/curation.py` | `tests/test_ingest.py` |
| tables, indexes | `secgraph/store/models.py` **and** a new file in `secgraph/store/migrations/versions/` | `tests/test_migrations.py` |
| read queries | `secgraph/store/repository.py` (SQL), `secgraph/query/service.py` (logic), `secgraph/query/views.py` (scope, masking) | `tests/test_query.py` |
| attack-graph projection | `secgraph/analytics/attack_graph.py` | `tests/test_analytics.py` |
| probability maths | `secgraph/analytics/probability.py`, `markov.py`, `paths.py`, `exploitability.py` | `tests/test_analytics_math.py`; update `docs/ANALYTICS_MATH.md` |
| what analytics endpoints return | `secgraph/analytics/service.py` | `tests/test_analytics.py` |
| an API route | `secgraph/api/routes/*.py`, body models in `secgraph/api/schemas.py` | `tests/test_api.py`; `make docs` |
| authentication, roles, audit, rate limits, guardrail | `secgraph/governance/` | `tests/test_governance.py`, `tests/test_api.py` |
| change feed, webhooks | `secgraph/events/` | `tests/test_api.py` |
| context packs, memory, MCP tools, vault | `secgraph/agents/` | `tests/test_api.py`, `tests/test_mcp.py` |
| the console | `secgraph/static/*.js`, `app.css`, `index.html` — no build step | `tests/test_console.py` |
| CLI commands | `secgraph/cli.py` | `tests/test_client_and_cli.py` |
| the Python client | `secgraph/client.py` (must not import the server) | `tests/test_client_and_cli.py` |
| settings | `secgraph/config.py` **and** `.env.example` | |
| container, compose, Kubernetes | `Dockerfile`, `docker-compose.yml`, `deploy/` | CI builds and starts the image |

Wiring: `secgraph/context.py` builds every service once (`AppContext`); routes get it through
`secgraph/api/deps.py`.

## Rules that are easy to break

- **Every query filters on `tenant_id`.** There is no global read.
- **Never return a store record directly.** Go through `Viewer` (`secgraph/query/views.py`) so type
  scope and PII masking apply. Out-of-scope is 404, not 403.
- **Do not query edges with `src IN (…) OR dst IN (…)`.** It defeats both endpoint indexes. Query
  each side separately (see `GraphReader.edges_of`).
- **Ingest paths lock rows in id order** (`with_for_update(key_share=True)`, `ORDER BY id`) and run
  through `Database.run`, which retries serialisation conflicts. Keep both or concurrent loads
  deadlock or lose updates.
- **Change events and audit entries are written in the same transaction as the change**, with
  sequence numbers allocated under the tenant row lock (`store/db.py: lock_tenant`).
- **Analytics are deterministic.** Anything random takes the configured seed. Anything expensive is
  memoised on the `AttackGraph` (`AnalyticsService._memoized`) and honours a time budget.
- **The console never uses `innerHTML`.** Build DOM with `h()` from `static/ui.js`; use `fill()` /
  `add()` rather than the native `append()` (which prints `null` and `[object …]`).
- **The CSP forbids inline script and external hosts.** No CDN links, no inline handlers.
- **No new runtime dependency without need**; if one is added, `make lock` and commit both lock
  files. Nothing may fetch from the network at run time.
- **Settings are `SECGRAPH_*` environment variables** in `config.py`; add new ones to `.env.example`.
- **Production refuses unsafe configuration** (`Settings.validate_for_environment`). Do not weaken it
  to make something start.

## Conventions

- Typed errors from `secgraph/errors.py`; messages name the field and what to do.
- `ruff format`, line length 120, `mypy` with `disallow_untyped_defs`.
- Tests use real databases and real HTTP through the app, not mocks of our own code. Each test has
  its own tenant (`tenant` fixture); `load(nodes=[…], edges=[…])` ingests a batch; `auth("analyst")`
  returns headers for an API key with that role.
- Docstrings say why. Comments explain a constraint, not the line below them.

## Documentation index

| File | Contents |
|---|---|
| `README.md` | what it is, how to start it |
| `docs/HANDOVER.md` | state of the project: verified, not verified, decisions pending |
| `docs/ARCHITECTURE.md` | components, data model, write and read paths, design decisions |
| `docs/ANALYTICS_MATH.md` | every formula, the proofs of the bounds, assumptions |
| `docs/DATA_ONBOARDING.md` | canonical format, mapping language, identity resolution, conflicts |
| `docs/AGENTS.md` | MCP, context packs, shared memory, vault, protective plane |
| `docs/INTEGRATION.md` | contracts with asset inventory, CRVM, Remediation OS, HAL-O, AgentPEP / Thoth |
| `docs/OPERATIONS.md` | install, configure, upgrade, back up, monitor, size, troubleshoot |
| `docs/SECURITY.md` | threat model, protections, known limitations |
| `docs/API.md`, `docs/openapi.json` | API conventions; generated schema |
| `docs/ONTOLOGY.md` | generated from the ontology file |
| `CHANGELOG.md` | what changed |

When you learn something that the next person would otherwise have to rediscover — a constraint, a
pitfall, a decision and its reason — add it to the relevant file above, and add a line here if it is
a rule.

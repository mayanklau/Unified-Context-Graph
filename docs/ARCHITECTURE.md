# Architecture

## The shape of it

```
                        ┌──────────────────────────── one process image ─────────────────────────────┐
  sources               │                                                                             │
  ───────               │   ingest                 store                  read                        │
  CSV / JSON files ────▶│  mappings ─▶ validate ─▶ resolve identity ─▶ PostgreSQL ─▶ query service ──▶│──▶ REST API
  canonical batches ───▶│  (YAML)     (ontology)   (identity spine)     nodes, edges    analytics      │──▶ console
                        │                 │                │            versions        context packs  │──▶ MCP (agents)
                        │            quarantine        conflicts        outbox, audit   memory         │──▶ vault export
                        │                                                   │                          │
                        │                                   worker: webhooks, expiry, retention ───────│──▶ signed webhooks
                        └─────────────────────────────────────────────────────────────────────────────┘
```

One Python package, one container image, three ways to run it: `secgraph serve` (API and console),
`secgraph worker` (webhook delivery and maintenance) and the `secgraph` CLI. PostgreSQL is the only
stateful dependency. There is no message broker, no cache server and no graph database to operate.

## Design decisions, and why

**PostgreSQL, not a graph database.** The platform this belongs to is sovereign and frequently
air-gapped; every additional stateful product is something a bank's operations team must patch,
back up and get through change control. The graph's hot paths — neighbourhood expansion, identifier
lookup, bulk upsert — are index lookups that PostgreSQL does well, and attack-path analytics run in
memory on a compact projection, not in the database. SQLite is supported for development and tests
only. The storage layer is confined to `secgraph/store`; nothing above it writes SQL.

**The ontology is data.** `secgraph/ontology/core.ontology.yaml` defines every node type, property,
identifier, relationship and — in `attack_semantics` — every rule by which an attacker moves and
every number those rules use. It is validated when loaded (a rule that names an unknown type stops
the process at start-up), its fingerprint is recorded with every ingest batch, and
`docs/ONTOLOGY.md` is generated from it. Changing how the graph models the world is a reviewed
change to one file.

**Identity resolution refuses to guess.** Identifiers are declared per type as *strong* (a serial
number, a cloud resource id: two records sharing one are the same entity), *weak* (a hostname, an
IP: evidence, not proof), or *exclusive* (an entity has at most one value: two different values
mean two entities). A record that strong identifiers tie to two different entities is not merged
and not dropped: both entities stay, the contradiction is stored as a conflict, and a steward
settles it. The settlement is remembered as a pin, so the same ambiguity does not come back with
the next load. See [DATA_ONBOARDING.md](DATA_ONBOARDING.md).

**Everything is versioned in place.** A node has a current row and a history of versions; an edge
is a slowly-changing row (`valid_from`, `valid_to`, current when `valid_to` is null) with a stable
lineage id. Reads accept `as_of` and return what the graph held at that moment. This is system
time — *what the graph knew* — alongside each record's own `first_seen` / `last_seen`.

**Changes and audit are written in the same transaction as the data.** Every committed change
appends to an outbox (`change_events`) with a per-tenant sequence number, and every privileged
action appends to a hash-chained audit log. Both sequences are allocated under a row lock on the
tenant, so they are gap-free and ordered. Consumers resume from the last sequence they saw; nothing
is lost if a consumer or the worker is down.

**Analytics are deterministic and explainable.** No model is trained. The attack graph is a pure
function of the stored graph and the ontology; the probabilities are closed-form over published
inputs (KEV, EPSS, CVSS) and recorded controls; and the one sampled quantity is seeded. Every
number in a response can be traced to a rule and its evidence. See
[ANALYTICS_MATH.md](ANALYTICS_MATH.md).

**Agents get a governed interface, not database access.** Agents read through the same permission
and masking layer as people, write only to shared memory, and both directions can be inspected by
the protective plane. See [AGENTS.md](AGENTS.md).

## Modules

| Path | Responsibility |
|---|---|
| `secgraph/ontology/` | Ontology model, the core ontology file, normalisation of identifiers, validation of properties and predicates, generated documentation |
| `secgraph/store/` | SQLAlchemy models, the `Database` (transactions, snapshots, retry on serialisation conflicts), `GraphReader`, Alembic migrations |
| `secgraph/ingest/` | Canonical record format, `IngestService` (validation, identity resolution, versioned upsert), declarative source mappings, curation (merge, conflicts, quarantine, expiry, retention) |
| `secgraph/query/` | Search, lookup, neighbourhood, subgraph, shortest path, pattern match, history — all scope- and PII-aware through `Viewer` |
| `secgraph/analytics/` | Attack-graph projection, exploitability scoring, probability bounds and estimate, K-best paths, Markov detection race, remediation priorities, choke points, blast radius |
| `secgraph/agents/` | Context packs, shared memory, MCP server, Markdown vault export |
| `secgraph/governance/` | Authentication (passwords, API keys, external JWTs), roles and scopes, audit chain, rate limiting, protective-plane hook and secret redaction |
| `secgraph/events/` | Transactional outbox and signed webhook delivery |
| `secgraph/api/` | FastAPI application, routes, error mapping, security headers |
| `secgraph/static/` | The console: dependency-free ES modules, no build step, no external assets |
| `secgraph/integrations/` | Connectors for the Agentic SOC Harness |
| `secgraph/client.py` | Python client for other products |
| `secgraph/cli.py`, `secgraph/worker.py` | Operations |

## Data model

| Table | Holds |
|---|---|
| `tenants` | One row per tenant; carries the change and audit sequence heads |
| `nodes`, `node_versions` | Current entities and their history |
| `node_aliases` | The identity spine: every identifier of every entity, with a partial unique index that makes a strong identifier belong to one entity |
| `edges` | Relationships, versioned in place; a partial unique index allows one current version per relationship |
| `resolution_conflicts` | Identity contradictions awaiting a decision |
| `ingest_batches`, `quarantined_records` | What was loaded, from where, with which ontology; and what was refused, with the reason |
| `change_events` | The outbox |
| `audit_log` | Hash-chained audit entries |
| `users`, `api_keys` | Credentials (PBKDF2-SHA256 password hashes; SHA-256 of API keys) |
| `memory_notes`, `memory_links`, `memory_terms` | Shared memory and its search index |
| `webhooks` | Subscriptions and their delivery cursor |

Every table carries `tenant_id`, and every query filters on it; the test suite gives each test its
own tenant so the boundary is exercised constantly.

## A write, end to end

1. A source file arrives at `POST /api/v1/ingest/source/{mapping}` (or a canonical batch at
   `POST /api/v1/ingest`). A mapping turns source records into canonical nodes and edges.
2. Each record is validated against the ontology. A bad record is quarantined with its reason; the
   rest of the batch proceeds.
3. Identifiers are normalised and looked up in the identity spine. The record updates the entity it
   resolves to, creates a new one, or raises a conflict.
4. Properties merge under source priority (`SECGRAPH_SOURCE_PRIORITY`): a lower-priority source does
   not overwrite a fresher value from a higher-priority one.
5. Changed entities get a new version; changed relationships close the current row and open a new
   one. Unchanged records only advance `last_seen`.
6. Change events and the batch record commit in the same transaction. Records are applied in chunks
   (500 by default), each its own transaction, retried on serialisation conflicts — concurrent
   loads of overlapping data are safe and are tested on PostgreSQL.

## A read, end to end

A request is authenticated (bearer token or API key), rate-limited per credential, and mapped to a
principal with permissions, an optional node-type scope, and a PII entitlement. Query and analytics
services read from a repeatable-read snapshot. `Viewer` applies the scope and masks personal data
on the way out. Analytics first obtain the tenant's attack graph, which is cached in the process:
it is reused while the tenant's change sequence has not moved, and for at most
`SECGRAPH_ANALYTICS_CACHE_TTL_SECONDS` after it has, so a busy ingest does not rebuild it on every
request. Every analytics response says which graph state it was computed from.

## Scaling

- The API is stateless; run as many replicas as needed. Each replica keeps its own attack-graph
  cache and its own rate-limit counters.
- Ingestion is CPU-bound in Python and safe to run concurrently; load independent sources in
  parallel.
- Attack-graph memory grows with the number of states and steps; limits
  (`SECGRAPH_ANALYTICS_MAX_NODES`, `_MAX_EDGES`) refuse a projection that would not fit rather than
  exhaust the pod.
- Measured numbers and sizing guidance are in [OPERATIONS.md](OPERATIONS.md#sizing).

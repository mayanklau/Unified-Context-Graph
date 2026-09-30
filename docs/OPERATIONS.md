# Operations

## What runs

| Process | Command | Count | State |
|---|---|---|---|
| API and console | `secgraph serve` | 1 or more | none (an in-memory analytics cache and rate-limit counters per process) |
| Worker | `secgraph worker` | 1 or more | none |
| Migrations | `secgraph migrate` | once per release | — |
| PostgreSQL 14+ (16 tested) | | 1 | everything |

The API listens on port 8080 over plain HTTP. Terminate TLS in front of it — an ingress, a load
balancer, or the nginx overlay shipped in `deploy/compose/docker-compose.tls.yml`.

## Installing

### Docker Compose (one host)

```bash
bash scripts/quickstart.sh            # add --demo for the demonstration estate
```

This writes `.env` with generated secrets (mode 600), builds the image, starts PostgreSQL, runs the
migrations, starts the API and the worker, and creates the first administrator, printing the
password once. Run it again at any time: it is idempotent, and it is also how you apply an upgrade.

With TLS (certificate and key from your CA in `deploy/nginx/certs/tls.crt` and `tls.key`):

```bash
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.tls.yml up -d
```

The containers run as a non-root user with a read-only root filesystem, no Linux capabilities and
`no-new-privileges`.

### Kubernetes

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n security-graph create secret generic secgraph-secrets \
  --from-literal=SECGRAPH_DATABASE_URL='postgresql+psycopg://secgraph:<password>@<host>:5432/secgraph' \
  --from-literal=SECGRAPH_JWT_SECRET="$(openssl rand -hex 48)" \
  --from-literal=SECGRAPH_METRICS_TOKEN="$(openssl rand -hex 24)"
# edit deploy/kubernetes/kustomization.yaml (image registry) and ingress.yaml (host name), then:
kubectl apply -k deploy/kubernetes
kubectl -n security-graph exec deploy/secgraph-api -- sh -c \
  'printf "%s\n" "<password>" | secgraph users create admin --roles admin --password-stdin'
```

The manifests give you: a migration Job, an API Deployment (2 replicas, probes, rolling updates, a
PodDisruptionBudget, the restricted Pod Security Standard), a worker Deployment, a ClusterIP
Service, default-deny ingress NetworkPolicies and an example Ingress. API pods wait for the schema
before starting. PostgreSQL is expected to be provided — the bank's managed service or an operator;
`postgres-dev.yaml` is a single-pod database for trying the manifests out only.

### Air-gapped

On a connected machine with Docker:

```bash
make airgap-bundle        # → dist/security-graph-<version>-airgap.tar.gz, with its SHA-256
```

The bundle holds the application and PostgreSQL images, the compose and Kubernetes files, the
Python wheels, the documentation, `install.sh` and a `SHA256SUMS` of its contents. On the isolated
host: unpack, check the sums, `bash install.sh`. For Kubernetes, `docker load` the images and push them
to the internal registry. `INSTALL-WITHOUT-DOCKER.txt` in the bundle covers a plain Python install.

The image itself builds without network access when `wheelhouse/` holds the wheels, which is how
the bundle script builds it (`docker build --network none`).

### Without containers (systemd)

```ini
# /etc/systemd/system/secgraph-api.service
[Unit]
Description=Security Graph API
After=network-online.target postgresql.service

[Service]
User=secgraph
EnvironmentFile=/etc/secgraph/secgraph.env
ExecStart=/opt/secgraph/bin/secgraph serve --host 127.0.0.1
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`secgraph-worker.service` is the same with `ExecStart=/opt/secgraph/bin/secgraph worker`.
`/etc/secgraph/secgraph.env` holds the `SECGRAPH_*` variables, mode 600.

## Configuration

Every setting is an environment variable; [.env.example](../.env.example) lists all of them with
their defaults. The ones that matter on day one:

| Variable | Set it to |
|---|---|
| `SECGRAPH_ENVIRONMENT` | `production` (the image default). Refuses SQLite, a default signing secret, a bootstrap password and CORS `*`. |
| `SECGRAPH_DATABASE_URL` | `postgresql+psycopg://user:password@host:5432/dbname` |
| `SECGRAPH_JWT_SECRET` | 32+ random characters; the same on every replica |
| `SECGRAPH_METRICS_TOKEN` | a token; `/metrics` then requires it |
| `SECGRAPH_SOURCE_PRIORITY` | your sources, most trusted first, e.g. `cmdb,edr,scanner` |
| `SECGRAPH_GUARDRAIL_WEBHOOK_URL` | the protective plane's check endpoint, if agents use the graph |
| `SECGRAPH_OIDC_PUBLIC_KEY_FILE`, `_ISSUER`, `_AUDIENCE` | to accept tokens from your identity provider |
| `SECGRAPH_DOCS_ENABLED` | `false` on an air-gapped network: `/docs` loads its viewer from a CDN. `/openapi.json` is always served. |

`secgraph doctor` checks configuration, ontology, mappings, database connectivity and schema version
and exits non-zero if anything is wrong. Run it after every change.

### Single sign-on

The graph verifies externally issued RS256/ES256 tokens offline against a PEM public key — no call
to the identity provider. The token needs `iss`, `exp`, `sub`, the expected `aud` when
`SECGRAPH_OIDC_AUDIENCE` is set, a roles claim (`SECGRAPH_OIDC_ROLES_CLAIM`, default `roles`) naming
Security Graph roles, and optionally a tenant claim (default tenant otherwise). Roles the graph does
not know are ignored, and `platform_admin` is never accepted from a token. Send it as a bearer token. The console's own sign-in form uses local accounts or an API key;
putting the console behind the organisation's SSO proxy is the usual arrangement.

## Users, keys and roles

```bash
secgraph users create alice --roles analyst --password-stdin
secgraph users set-password alice --password-stdin
secgraph users disable alice
secgraph keys create --name "remediation-os" --kind service --roles integration
secgraph keys list
secgraph keys revoke <key id>
```

or **Administration** in the console.

| Role | For | Can |
|---|---|---|
| `viewer` | read-only staff | read the graph (personal data masked) |
| `analyst` | SOC and exposure analysts | read, analytics, shared memory, personal data |
| `agent` | AI agents | read, analytics, shared memory; personal data masked |
| `ingest` | connectors | write graph data, nothing else |
| `steward` | data owners | read, write, merge, resolve conflicts, quarantine |
| `integration` | other products | read, analytics, change feed |
| `auditor` | audit and risk | read, audit log, change feed |
| `admin` | tenant administrators | everything within the tenant |
| `platform_admin` | platform operators | everything, any tenant (CLI only) |

Five failed sign-ins lock an account for 15 minutes (`SECGRAPH_LOGIN_MAX_FAILURES`,
`_LOCKOUT_SECONDS`).

## Upgrading

1. Read `CHANGELOG.md` for the release.
2. Back up the database.
3. Deploy the new image. With Compose: `bash scripts/quickstart.sh`. With Kubernetes: update the image
   tag and the Job name in `migrate-job.yaml`, then `kubectl apply -k`.
4. `secgraph doctor`.

Migrations are forward-only in production; the rollback for a bad release is restoring the backup.
`secgraph migrate status` shows the current and expected revisions.

## Backup and restore

All state is in PostgreSQL.

```bash
pg_dump --format=custom --file=secgraph-$(date +%F).dump "$DATABASE_URL"
pg_restore --clean --if-exists --dbname="$DATABASE_URL" secgraph-2026-09-30.dump
```

After a restore, run `secgraph doctor` and `secgraph verify-audit`. Keep `.env` (the signing
secret) with your secrets, not with the database dump. Losing the signing secret only signs
everyone out; losing the database loses the graph.

## Monitoring

| Endpoint | Meaning |
|---|---|
| `GET /health` | the process is up |
| `GET /ready` | the database answers and the ontology is loaded |
| `GET /metrics` | Prometheus metrics (bearer token if `SECGRAPH_METRICS_TOKEN` is set) |

Worth alerting on:

| Metric | Why |
|---|---|
| `secgraph_http_requests_total{status=~"5.."}` | server errors |
| `secgraph_http_request_seconds` | latency |
| `secgraph_quarantine_open` | records refused and waiting; a jump usually means a source changed format |
| `secgraph_resolution_conflicts_total` | identity conflicts raised |
| `secgraph_webhook_deliveries_total{outcome!="delivered"}` | a consumer is not receiving changes |
| `secgraph_guardrail_decisions_total{decision="error"}` | the protective plane is unreachable |
| `secgraph_auth_events_total`, `secgraph_rate_limited_total` | sign-in failures, throttling |
| `secgraph_analytics_seconds` | attack-graph build and query times |

Logs are JSON on standard output, one object per line, each carrying `request_id` (also returned as
`X-Request-ID`), `tenant` and `principal`. Secrets and request bodies are not logged.

The audit log is hash-chained per tenant: each entry includes the hash of the one before.
`secgraph verify-audit` (or `GET /api/v1/audit/verify`) recomputes the chain and reports the first
entry that does not match. Schedule it, and export the audit log to the SIEM.

## Sizing

Measured with `scripts/benchmark.py --database-url …` (`make bench` runs it on SQLite) on a synthetic,
bank-shaped estate, PostgreSQL 16 on the same host,
**two CPU cores and 7 GB of memory**. Treat these as a floor for planning; run the benchmark on
your own hardware before committing to a size.

| | 10,000 assets | 50,000 assets |
|---|---|---|
| Entities / relationships | 34,000 / 71,000 | 165,000 / 355,000 |
| First load | 69 s (1,500 records/s) | 321 s (1,600 records/s) |
| Reload, nothing changed | 45 s (2,300 records/s) | 229 s (2,300 records/s) |
| Lookup by identifier | 2 ms | 4 ms |
| Neighbours of one entity | 7 ms | 7 ms |
| Subgraph, depth 2 | 34 ms | 34 ms |
| Attack graph (states / steps) | 12,000 / 35,000 | 60,000 / 176,000 |
| Build the attack graph (once per graph change) | 4 s | 21 s |
| Overview with the sampled estimate (first call) | 1 s | 7 s |
| Top attack paths | 10 ms | 10 ms |
| Remediation priorities | 10 s (time budget) | 10 s (time budget) |
| Detection race (first call) | 2 s | 12 s |
| Peak memory of one process doing all of the above | 310 MB | 900 MB |

The 10,000-asset column was measured on an idle machine with the code as shipped. The
50,000-asset column was measured while other work was running on the same two cores and before
two later improvements (statistics refresh during bulk loads; caching of the detection race), so
its load and analytics times are pessimistic.

What follows from this:

- **Queries do not slow down as the estate grows.** They are index lookups.
- **Ingestion is CPU-bound in the application**, at roughly 1,500–2,300 records per second per
  process. A 100,000-asset estate is on the order of a million records: about ten minutes for a
  first load, less for the daily reload. Loads of different sources can run in parallel.
- **Analytics memory and build time grow linearly** with the attack graph. Allow about 1 GB per
  50,000 assets for an API replica, plus headroom; the Kubernetes manifest's 4 GiB limit is sized
  for roughly 150,000 assets.
- **Analytics results are computed once per graph state and reused**; the first caller after a
  change pays, later callers do not.
- **PostgreSQL**: 2 vCPU and 4 GB is enough for the sizes above. Storage grows with change volume
  because history is kept; start with 20 GB and watch it.

Starting points:

| Estate | API replicas | API memory limit | PostgreSQL |
|---|---|---|---|
| up to 10,000 assets | 2 × 0.5 vCPU | 1 GiB | 2 vCPU, 4 GB, 20 GB disk |
| up to 50,000 assets | 2 × 1 vCPU | 2 GiB | 2 vCPU, 8 GB, 50 GB disk |
| up to 150,000 assets (extrapolated, not measured) | 2–3 × 2 vCPU | 4 GiB | 4 vCPU, 16 GB, 100 GB disk |

## Routine maintenance

The worker does this on its own every hour (`SECGRAPH_MAINTENANCE_INTERVAL_SECONDS`): retires
elements whose type has a `ttl_days` and that no source has reported for that long, prunes the
change feed (`SECGRAPH_CHANGE_RETENTION_DAYS`, 30) and old versions
(`SECGRAPH_HISTORY_RETENTION_DAYS`, 0 = keep), and archives expired memory notes.
`secgraph worker --once` runs one pass, for a scheduler instead of a long-running worker.

PostgreSQL's autovacuum is sufficient at the measured scales. The versioned tables (`node_versions`,
`edges`) grow with change volume, not estate size; set history retention if that matters.

## Troubleshooting

| Symptom | Look at |
|---|---|
| The API will not start: "unsafe production configuration" | the message lists each problem; usually the signing secret or the database URL |
| `/ready` is 503 | the database: `secgraph doctor` |
| Everything is 401 after a restart | replicas have different `SECGRAPH_JWT_SECRET` values |
| 429 responses | `SECGRAPH_RATE_LIMIT_PER_MINUTE`; limits are per credential and per replica |
| A load reports quarantined records | **Data quality → Quarantine** gives the reason per record |
| An entity appears twice | **Data quality → Identity conflicts**; then merge or resolve ([DATA_ONBOARDING.md](DATA_ONBOARDING.md)) |
| Attack-path numbers did not move after a load | the attack graph is reused for up to `SECGRAPH_ANALYTICS_CACHE_TTL_SECONDS` (300) after the graph changes; every analytics response carries `graph.built_at` and `graph.change_seq` |
| `"partial": true` in priorities or choke points | the time budget ended first; pass `time_budget_s` up to 60 |
| 413 "the attack graph has more than … states" | raise `SECGRAPH_ANALYTICS_MAX_NODES` / `_MAX_EDGES` and the pod's memory together |
| A webhook stopped | **Administration → Webhooks** shows the last error; it is disabled after 8 consecutive failures and resumes from where it stopped when re-enabled |

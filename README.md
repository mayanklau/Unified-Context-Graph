# Security Graph

One graph of everything the security organisation needs to reason about — assets, identities,
software, vulnerabilities, findings, controls, detections, business services, data stores, and the
AI agents, models and tools now working alongside them — with explainable attack-path maths on top
and a governed interface for the agents that use it.

It runs entirely on your own infrastructure. Nothing is fetched from, or sent to, the internet.

```
 asset inventory ─┐                                             ┌─ console (people)
 CMDB / directory ─┤   ingest      ┌───────────────────┐  query  ├─ REST API + Python client (products)
 scanners / SBOM ──┼──────────────▶│   Security Graph   │────────▶├─ MCP server (agents)
 NVD · KEV · EPSS ─┤  identity     │  PostgreSQL-backed │ analyse ├─ change feed + webhooks (CRVM, Remediation OS)
 SIEM / EDR (OCSF) ┘  resolution   └───────────────────┘         └─ Markdown vault (file-based agents)
```

## Start it

Pick one. Each ends with a console at `http://127.0.0.1:8080` and a demonstration bank
("Meridian Bank": 110 entities, 185 relationships, four shared-memory notes) already loaded.

**With Docker** — PostgreSQL, API and worker, production settings:

```bash
git clone <this repository> && cd security-graph
bash scripts/quickstart.sh --demo
```

The script generates the secrets, builds the image, starts the stack, creates the first
administrator and prints the password once. Leave off `--demo` for an empty graph.

**Without Docker** — Python 3.11+, SQLite, development settings:

```bash
make demo          # sign in as admin / Meridian-Demo-2026
```

**Air-gapped** — build a bundle on a connected machine, carry it across:

```bash
make airgap-bundle                       # → dist/security-graph-1.0.0-airgap.tar.gz
# on the isolated host:
tar xzf security-graph-1.0.0-airgap.tar.gz && cd security-graph-1.0.0-airgap && bash install.sh --demo
```

Kubernetes manifests are in [`deploy/kubernetes`](deploy/kubernetes); see
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## What you get

| | |
|---|---|
| **An ontology you own** | 17 entity types and 32 relationship types in one reviewed YAML file ([docs/ONTOLOGY.md](docs/ONTOLOGY.md)). The graph refuses what the ontology does not describe. Change the file, not the code. |
| **An identity spine** | The same host arrives from the CMDB, the scanner and the EDR under three names; it becomes one entity. Ambiguity is recorded as a conflict for a person to settle — never guessed. |
| **History** | Every entity and relationship is versioned. Ask what the graph knew at any past moment (`as_of`). |
| **Attack paths you can defend** | Compromise probability for every crown jewel as a **proven lower bound, a proven upper bound and a seeded estimate** — and each step of each path shows the rule, the finding, the EPSS/KEV/CVSS evidence and the controls behind its number. No model is trained; the same graph always gives the same answer. |
| **What to fix first** | Each candidate fix is scored by recomputing the attack graph as if it were done. Choke points show where one control protects many crown jewels. |
| **An interface for agents** | An MCP server with 18 tools, token-budgeted context packs, and shared memory in which notes that proved right are suggested first. Everything an agent reads or writes can be routed through your protective plane (AgentPEP / LLM Firewall / Thoth). |
| **Governance** | Tenants, roles, type-scoped API keys, PII masking, rate limits, a hash-chained audit log, and an ordered change feed with signed webhooks. |

## Five minutes with the demo

```bash
export SG=http://127.0.0.1:8080
TOKEN=$(curl -s $SG/api/v1/auth/token -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<the password>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"

curl -s -H "$AUTH" "$SG/api/v1/lookup?value=10.10.1.10"                 # who is this IP?
curl -s -H "$AUTH" "$SG/api/v1/analytics/overview"                      # how exposed are the crown jewels?
curl -s -H "$AUTH" "$SG/api/v1/analytics/attack-paths?limit=3"          # how would an attacker get there?
curl -s -H "$AUTH" "$SG/api/v1/analytics/remediation-priorities?by=vulnerability&limit=5"
```

The same from Python ([examples/quickstart.py](examples/quickstart.py)):

```python
from secgraph.client import SecurityGraphClient

with SecurityGraphClient("http://127.0.0.1:8080", api_key="sg_…") as graph:
    host = graph.lookup("web-portal-01")[0]
    print(graph.exposure(host["id"])["compromise_probability"])
    for fix in graph.remediation_priorities(by="vulnerability", limit=5)["items"]:
        print(fix["vulnerability"], fix["risk_reduction_percent"])
```

And for an agent: point any MCP client at `POST /mcp` with an API key
([docs/AGENTS.md](docs/AGENTS.md), [examples/mcp.json](examples/mcp.json)).

## Loading your own data

Ten source formats work out of the box — asset and identity CSVs, scanner CSVs, CycloneDX SBOMs,
NVD, CISA KEV, EPSS, ATT&CK STIX, and OCSF vulnerability and detection findings:

```bash
secgraph ingest assets.csv --mapping assets_csv
secgraph ingest nvdcve-2.0-recent.json --mapping nvd_cve
curl -H "X-API-Key: $KEY" --data-binary @findings.csv "$SG/api/v1/ingest/source/vuln_findings_csv"
```

A new source is a YAML mapping, not code: [docs/DATA_ONBOARDING.md](docs/DATA_ONBOARDING.md).

## Documentation

| Read this | When you want to |
|---|---|
| [docs/HANDOVER.md](docs/HANDOVER.md) | take the project over: what is verified, what is not, what to decide first |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | understand how it is built and why |
| [docs/ANALYTICS_MATH.md](docs/ANALYTICS_MATH.md) | check the maths: formulas, proofs of the bounds, what each number means |
| [docs/DATA_ONBOARDING.md](docs/DATA_ONBOARDING.md) | connect a source, write a mapping, resolve conflicts |
| [docs/AGENTS.md](docs/AGENTS.md) | connect an agent: MCP, context packs, shared memory, the vault |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | wire in asset inventory, CRVM, Remediation OS, HAL-O, AgentPEP / Thoth |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | deploy, configure, upgrade, back up, monitor, size |
| [docs/SECURITY.md](docs/SECURITY.md) | review the threat model and hardening |
| [docs/API.md](docs/API.md), [docs/openapi.json](docs/openapi.json) | call the API |
| [docs/ONTOLOGY.md](docs/ONTOLOGY.md) | see every type, property and attack rule |
| [CONTRIBUTING.md](CONTRIBUTING.md), [CLAUDE.md](CLAUDE.md) | change the code (the second is the map for coding agents) |

## Developing

```bash
make install      # .venv with pinned, hash-checked dependencies
make check        # lint, type-check, tests
make help         # everything else
```

Tests run on SQLite by default and on PostgreSQL when `SECGRAPH_TEST_DATABASE_URL` is set; CI does
both, plus browser tests of the console and a build-and-start test of the container image.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

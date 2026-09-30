# Integrating with the platform

The Security Graph is the shared picture underneath the platform's products. Each product gives it
what it knows and takes back what it needs; none of them needs to know about the others.

```
  Asset inventory ──▶ Inventory insights ──▶ CRVM ──▶ Remediation OS ──▶ HAL-O (agentic SOC)
        │ assets            │ enrichment       │ findings      │ fixes applied      │ alerts, decisions
        ▼                   ▼                  ▼               ▼                    ▼
  ┌──────────────────────────────── Security Graph ────────────────────────────────────┐
  │  one entity per real thing · history · attack paths · priorities · shared memory    │
  └─────────────────────────────────────────────────────────────────────────────────────┘
        ▲ every read by an agent and every write to memory can pass through ▲
                        AgentPEP · LLM Firewall · Thoth
```

What ships in this repository is the graph's side of each contract — the endpoints, the formats,
the Python client, and for the Agentic SOC Harness a working pair of connectors. The adapter inside
each product (the scheduled export, the webhook receiver) is that product's to add; each section
below says exactly what it has to do.

Give every product its own API key with the narrowest role that works (`secgraph keys create`, or
**Administration → API keys**). All calls below take `X-API-Key: <key>`.

## Asset inventory → graph

**Gives:** assets, their identifiers, network segments, the business services they support.
**Role:** `ingest`.

If the inventory can export CSV with the columns `assets_csv` reads (the mapping file lists them),
no code is needed:

```bash
curl -H "X-API-Key: $KEY" --data-binary @assets.csv "$SG/api/v1/ingest/source/assets_csv"
```

Otherwise write a mapping for its native export ([DATA_ONBOARDING.md](DATA_ONBOARDING.md);
`config/mappings/example_cmdb.yaml` is a worked example), or post canonical batches directly.
Send the full inventory on a schedule; unchanged records cost little and keep `last_seen` current,
which is what lets stale assets be retired.

**Takes back:** nothing required. Useful: `GET /api/v1/conflicts` — places where the inventory and
another source disagree about what a machine is — is a data-quality feed for the inventory team.

## Inventory insights ↔ graph

**Gives:** derived facts as properties on assets (`internet_exposed`, `crown_jewel`, `criticality`,
`owner`), as a second source. Set `SECGRAPH_SOURCE_PRIORITY` so that a curated insight outranks a
raw discovery value, or the other way round, as the organisation prefers.
**Takes back:** the joined view for its own analysis —

| Need | Call |
|---|---|
| everything known about one asset | `GET /api/v1/lookup?value=<host, ip or id>` then `GET /api/v1/nodes/{id}` |
| assets matching a condition | `GET /api/v1/nodes?type=Asset&where={"internet_exposed":true,"criticality":{"gte":4}}` |
| assets related in a given way (say, internet-exposed assets with an open known-exploited finding) | `POST /api/v1/query/match` with a pattern ([API.md](API.md)) |
| what changed since yesterday | `GET /api/v1/changes?after=<sequence>` |

**Role:** `integration` to read; `ingest` to write.

## CRVM ↔ graph

**Gives:** findings and the vulnerabilities they are instances of (`vuln_findings_csv`,
`ocsf_vulnerability_finding`, or canonical batches); vulnerability intelligence (`nvd_cve`,
`cisa_kev`, `epss_csv`); risk acceptances (finding `status: risk_accepted`, `exception_until`,
`exception_reason`). **Role:** `ingest`.

**Takes back:** the ranking. This is the main integration.

```bash
curl -H "X-API-Key: $KEY" "$SG/api/v1/analytics/remediation-priorities?by=vulnerability&limit=50"
```

Each item is a fix — one vulnerability everywhere it occurs (`by=vulnerability`), one finding, or
one asset — with `risk_reduction_percent` (the share of crown-jewel risk that closing it removes,
computed by re-evaluating the attack graph with the fix applied), the assets it is on, whether it is
known-exploited, and the crown jewels it protects most. CRVM can show this beside CVSS and its own
scores; it answers a different question (what does closing this buy us *here*) from a different
input (the organisation's own topology and controls).

Also useful: `GET /api/v1/analytics/nodes/{id}/exposure` per asset, and
`GET /api/v1/analytics/attack-paths?target_id=…` to show *why* a finding matters.
**Role:** `integration`.

## Remediation OS ↔ graph

**Takes:** what to fix and where one control does the most good —
`/analytics/remediation-priorities` and `/analytics/choke-points` (states on the most likely paths,
with the controls that would help and are not there).

**Gives back:** what it did. When a patch lands, the next scanner load closes the finding. When a
compensating control is applied instead — a virtual patch, a WAF rule — record it, because the
attack-path maths take it into account immediately:

```json
{"source": "remediation-os",
 "nodes": [{"type": "Control", "ref": "c",
            "identifiers": {"control_key": "ros:vpatch:CVE-2024-3400:vpn-gw-01"},
            "properties": {"name": "Virtual patch for GlobalProtect", "control_type": "virtual_patching",
                           "effectiveness": 0.8, "status": "active"}}],
 "edges": [{"type": "MITIGATES", "source": {"ref": "c"},
            "target": {"type": "Finding", "identifiers": {"finding_key": "<the finding>"}}}]}
```

**Subscribes to changes**, so it learns about new findings and closed ones without polling:

```bash
curl -H "X-API-Key: $ADMIN_KEY" -H 'content-type: application/json' "$SG/api/v1/webhooks" -d '{
  "name": "remediation-os", "url": "https://ros.bank.example/hooks/security-graph",
  "event_kinds": ["node.created", "node.updated", "node.deleted"], "entity_types": ["Finding"]}'
```

Deliveries are batches of events, in order, at least once, signed:

```
X-SecGraph-Timestamp: 1790612345
X-SecGraph-Signature: sha256=<HMAC-SHA256 of "<timestamp>.<body>" with the subscription's secret>
X-SecGraph-Delivery:  <id>
```

The receiver verifies the signature, rejects old timestamps, and treats a repeated sequence number
as already processed. A receiver that would rather pull uses `GET /api/v1/changes?after=<sequence>`
with the same events. **Roles:** `integration` to read, `ingest` to write, an `admin` to create the
subscription.

## HAL-O and the Agentic SOC Harness ↔ graph

**Gives:** alerts, incidents and indicators (`ocsf_detection_finding`, or canonical batches), and —
through shared memory — what its agents and analysts learned.

**Takes:** context. Three ways, all described in [AGENTS.md](AGENTS.md):

- **MCP**: point the agent at `POST /mcp` with an `agent` key. Eighteen tools; the server's
  instructions tell the agent the usual flow.
- **Harness connectors**: `secgraph.integrations.ash.GraphAssetConnector` and
  `GraphVulnerabilityConnector` satisfy the harness's `AssetConnector` and `VulnerabilityConnector`
  protocols. Existing harness tools then read from the graph unchanged, and the asset they get back
  includes its attack exposure. This pair is tested against the harness's protocol definitions.
- **Context packs**: `GET /api/v1/context/{alert id}?budget_tokens=1500` returns a briefing on the
  alert *and the entity it fired on* — exposure, findings, controls, related detections, and notes
  from similar situations — sized to fit a prompt.

The loop worth closing: before acting an agent calls `suggest_from_memory`; after acting it calls
`remember` and later `memory_feedback`. Notes that worked are suggested first next time.
**Role:** `agent`.

## AgentPEP, the LLM Firewall and Thoth

Two integrations, in opposite directions.

**The graph calls the protective plane.** Set `SECGRAPH_GUARDRAIL_WEBHOOK_URL`. Every context pack
handed to an agent (`context.read`) and every note an agent writes (`memory.write`) is posted there
first as `{"stage", "payload", "meta"}` and proceeds only on `{"allow": true}`; a returned `payload`
replaces the original. Fail-closed by default. The contract is the harness's guardrail webhook, so
one policy service serves both.

**The graph models the protective plane.** Agents, models and tools are entities: an `AIAgent`
`USES_MODEL` an `AIModel`, `CAN_INVOKE` a `Tool` that `TOOL_TARGETS` assets, `ACTS_AS` an identity,
`READS_FROM` and `WRITES_TO` data stores. The attack rules treat these as ways an attacker moves —
content planted in a store an agent reads, a hijacked agent using its tools and identity — and treat
`llm_firewall`, `semantic_firewall`, `agent_policy_enforcement`, `tool_sandboxing` and
`human_in_the_loop` controls as what reduces them. Register each deployment of AgentPEP, the LLM
Firewall and Thoth as a `Control` that `PROTECTS` the agents it covers, and the attack-path results
show what the protective plane is worth and where an agent is outside it. The demonstration estate
includes two agents wired this way.

## The Python client

```python
from secgraph.client import SecurityGraphClient

with SecurityGraphClient(
    "https://security-graph.bank.example", api_key="sg_…", verify="/etc/ssl/certs/bank-ca.pem"
) as graph:
    graph.ingest_source("assets_csv", open("assets.csv", "rb").read())
    for change in graph.iter_changes(after=last_seen_sequence):
        handle(change)
```

It covers the whole API, raises `SecurityGraphError` with the server's error code, message and
request id, and depends only on `httpx`. Reads are retried on connection failures and on 429, 502,
503 and 504; writes are sent once — ingestion is idempotent, so sending a batch again is safe, but
that is left to the caller.

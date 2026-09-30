# Agents

Agents use the Security Graph through a governed interface, never through the database. There are
four ways in, all behind the same authentication, permissions, type scope and personal-data
masking as the REST API.

| Interface | For | How |
|---|---|---|
| **MCP server** | any MCP-capable agent or framework | `POST /mcp`, or `secgraph mcp` over stdio |
| **Context packs** | an agent that needs a briefing on one entity within a token budget | `GET /api/v1/context/{id}` or the `get_context` tool |
| **Shared memory** | agents and analysts leaving notes for each other | `/api/v1/memory…` or the memory tools |
| **Markdown vault** | file-based agents and offline review | `secgraph export-vault` or `GET /api/v1/export/vault` |

## Give an agent access

Create a key with the `agent` role (graph, analytics and memory; no personal data, no ingestion,
no administration). Optionally confine it to some entity types.

```bash
secgraph keys create --name "hal-o triage" --kind agent --roles agent
secgraph keys create --name "patch agent" --kind agent --roles agent --node-types Asset,Finding,Vulnerability,Software
```

The key is shown once. A type-scoped key cannot see other types anywhere — search, neighbours,
context, memory links — and cannot call the attack-path tools, which need the whole graph.

## MCP

**Over HTTP** (Streamable HTTP transport, JSON responses):

```json
{
  "mcpServers": {
    "security-graph": {
      "type": "http",
      "url": "https://security-graph.bank.example/mcp",
      "headers": {"X-API-Key": "sg_…"}
    }
  }
}
```

**Over stdio**, for clients that launch a local process. With `--url` the process is a thin relay
to a running server, so the agent host needs no database access:

```json
{
  "mcpServers": {
    "security-graph": {
      "command": "secgraph",
      "args": ["mcp", "--url", "https://security-graph.bank.example"],
      "env": {"SECGRAPH_API_KEY": "sg_…"}
    }
  }
}
```

Both are in [examples/mcp.json](../examples/mcp.json). Interoperability is tested against the
official MCP Python SDK. The server implements protocol versions 2025-06-18, 2025-03-26 and
2024-11-05; a client that offers a newer version is answered with the newest of these, which is the
protocol's own negotiation rule.

### Tools

| Tool | Does | Needs |
|---|---|---|
| `search_entities` | find entities by text, type and property predicate | `graph:read` |
| `get_entity` | one entity by id or by any identifier (host name, IP, CVE, account) | `graph:read` |
| `get_neighbors` | directly related entities | `graph:read` |
| `get_context` | token-budgeted briefing on one entity | `graph:read` |
| `find_path` | shortest relationship path between two entities | `graph:read` |
| `match_pattern` | match a typed path pattern | `graph:read` |
| `entity_history` | every recorded version of an entity | `graph:read` |
| `describe_ontology` | the types, relationships and attack rules in force | `graph:read` |
| `graph_stats` | counts by type | `graph:read` |
| `risk_overview` | entry points, crown jewels at risk, expected impact | `analytics:read` |
| `attack_paths` | most probable attack paths, each step explained | `analytics:read` |
| `node_exposure` | how exposed one entity is, through what, leading where | `analytics:read` |
| `blast_radius` | assume compromise: what is reachable, which services suffer | `analytics:read` |
| `remediation_priorities` | fixes ranked by the risk each removes | `analytics:read` |
| `recall_memory` | search shared notes | `memory:read` |
| `suggest_from_memory` | notes from similar situations, best-proven first | `memory:read` |
| `remember` | write a note | `memory:write` |
| `memory_feedback` | record that a note was used and whether it worked | `memory:write` |

`tools/list` returns only the tools the calling key may use. Arguments are validated against each
tool's schema; results are JSON text, capped in size.

## Context packs

```bash
curl -H "X-API-Key: $KEY" "$SG/api/v1/context/<node id>?budget_tokens=1500"
```

One call returns, in priority order and stopping at the budget:

1. what the entity is — properties, identifiers, sources, when it was seen;
2. its attack exposure — compromise probability with bounds, the most likely path in, open findings
   with their evidence, controls, crown jewels reachable from it;
3. its relationships, grouped and counted;
4. detections and incidents touching it;
5. shared-memory notes linked to it, and notes from similar situations, best-proven first.

For an alert, incident or finding, the pack also describes the entity it is about. The response
carries the rendered text, the sections, a token estimate, whether anything was cut, and
`provenance`: the ids of every entity and note the text drew on, so any statement can be checked.

## Shared memory

Agents working different cases look at the same graph, so what one learns can help the next.

```bash
curl -H "X-API-Key: $KEY" -H 'content-type: application/json' "$SG/api/v1/memory" -d '{
  "kind": "lesson",
  "title": "Log4Shell on an internet-facing Java tier: block at the WAF first, patch second",
  "body": "A WAF rule for JNDI lookup strings cut exploit attempts to zero within minutes …",
  "entity_ids": ["<asset id>", "<vulnerability id>"],
  "tags": ["log4shell", "waf"]
}'
```

- **Kinds:** `observation`, `decision`, `lesson`, `playbook`, `hypothesis`.
- **Linked to entities.** A note appears in the context pack of every entity it is linked to.
- **Signature.** Each note records features of the situation it came from — the types involved, the
  technique, the CVE, tags. `POST /api/v1/memory/suggest` takes the entities (or features) of the
  situation at hand and returns notes whose signature resembles it.
- **Proven notes first.** `POST /api/v1/memory/{id}/feedback` with `used`, `success` or `failure`
  records how a note fared. Ranking multiplies similarity by the lower end of a confidence interval
  on the success rate, so one lucky success does not outrank ten out of eleven.
- **Supersede, don't edit.** A note can replace an earlier one (`supersedes`); the old one stops
  being suggested and stays in the record.
- **Expiry.** `ttl_days` for notes that should not outlive a situation (a temporary risk
  acceptance).

### Notes are data, not instructions

A note is free text written by an agent, possibly after reading attacker-controlled content. The
graph therefore:

- redacts obvious secrets before storing (private keys, cloud access keys, bearer tokens, JWTs, its
  own API keys, credentials in URLs, `password=…` assignments) and reports what it redacted;
- bounds sizes;
- sends the note to the protective plane before it is stored, when one is configured;
- hands notes back clearly delimited as reference material, and tells MCP clients in the server
  instructions never to treat note text or entity descriptions as instructions.

None of this makes stored text safe to obey. An agent that acts on what it reads still needs its
own policy enforcement — that is what AgentPEP is for.

## The protective plane

Set `SECGRAPH_GUARDRAIL_WEBHOOK_URL` and two things are checked before they happen:

| Stage | Sent | Effect of `allow: false` |
|---|---|---|
| `memory.write` | kind, title, body, tags | the note is refused |
| `context.read` | the rendered context pack | the pack is withheld |

Request `{"stage": …, "payload": {…}, "meta": {tenant, principal, …}}`; response
`{"allow": true|false, "reason": "…", "payload": {…optional replacement…}}`. A replacement payload
is used in place of the original (for redaction). This is the same contract as the Agentic SOC
Harness guardrail webhook. `SECGRAPH_GUARDRAIL_FAIL_CLOSED=true` (the default) refuses when the
protective plane cannot be reached.

## The Markdown vault

```bash
secgraph export-vault ./vault          # or: GET /api/v1/export/vault  → tar.gz
```

One Markdown page per entity, grouped in a folder per type, relationships as `[[wiki links]]`,
memory notes alongside, and a `CLAUDE.md` at the root that tells an agent how the vault is laid out
and where to start. It opens as-is in any Markdown tool that understands wiki links. The export
honours the caller's scope and masking. It is a snapshot: regenerate it, don't edit it.

## The Agentic SOC Harness

```python
from secgraph.client import SecurityGraphClient
from secgraph.integrations.ash import GraphAssetConnector, GraphVulnerabilityConnector

graph = SecurityGraphClient("https://security-graph.bank.example", api_key="sg_…")
assets, vulns = GraphAssetConnector(graph), GraphVulnerabilityConnector(graph)
```

These satisfy the harness's `AssetConnector` and `VulnerabilityConnector` protocols, so its
existing tools read from the graph unchanged. `asset_id` may be a graph id or anything the identity
spine knows the asset by — host name, FQDN, IP, EDR agent id, inventory id.

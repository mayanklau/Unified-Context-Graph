# API guide

The complete, machine-readable description is [openapi.json](openapi.json) (also served at
`/openapi.json`; regenerate with `make docs`). This page covers what a schema does not say.

## Conventions

**Base path** `/api/v1`. JSON in, JSON out. Times are ISO 8601 in UTC.

**Authentication** — one of:

```
X-API-Key: sg_…                      services and agents
Authorization: Bearer <token>        people (POST /api/v1/auth/token) or your identity provider's token
```

`GET /api/v1/auth/me` returns who the caller is, their roles, permissions and type scope.

**Tenancy.** A credential belongs to one tenant and sees only that tenant. A platform administrator
can act on another tenant with `X-Tenant-ID`.

**Errors** always have this shape, and the HTTP status matches:

```json
{"error": {"code": "validation_failed", "message": "Asset.criticality: 9 is greater than the maximum 5",
           "detail": {}, "request_id": "7096ed31cdb14370ad6d2fafff2bf5e9"}}
```

| Status | Meaning |
|---|---|
| 400 / 422 | the request is malformed or fails validation; the message names the field |
| 401 | missing or invalid credential |
| 403 | the credential lacks the permission, or the protective plane refused |
| 404 | no such entity — also returned for entities outside the caller's scope |
| 409 | conflict (for example, merging entities of different types) |
| 413 | body or result larger than the configured limit |
| 429 | rate limit; `Retry-After` says when to retry |

Quote `request_id` (also the `X-Request-ID` response header) when reporting a problem: it is on
every log line the request produced.

**Lists** return `{"items": […], "total": n}` and take `limit` and `offset`. The change feed and the
audit log page by sequence instead (`after`).

**Time travel.** Most reads take `as_of=<timestamp>` and answer from what the graph held then.

**Personal data.** Identifiers and properties the ontology marks sensitive are masked unless the
credential holds `pii:read`. Masked values are stable pseudonyms, so they can still be compared.

## Property predicates

Anywhere a `where` is accepted:

```json
{"internet_exposed": true, "criticality": {"gte": 4}, "os": {"contains": "windows"},
 "environment": {"in": ["production", "dr"]}, "owner": {"exists": false}}
```

Operators: `eq` (the default), `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`, `exists`, `contains`.
All conditions must hold. Property names are checked against the ontology.

## Finding things

```bash
# by any identifier — host name, FQDN, IP, MAC, serial, CVE, account, e-mail
curl -H "$AUTH" "$SG/api/v1/lookup?value=10.10.1.10"

# by text, type and properties
curl -H "$AUTH" --get "$SG/api/v1/nodes" --data-urlencode 'type=Asset' \
     --data-urlencode 'where={"internet_exposed": true, "criticality": {"gte": 4}}'

# neighbours, optionally restricted
curl -H "$AUTH" "$SG/api/v1/nodes/<id>/neighbors?direction=out&edge_type=HAS_FINDING"
```

### Pattern match

A linear path: a start, then steps. Each step follows an edge type in a direction to a node that
satisfies a type and predicate.

```bash
curl -H "$AUTH" -H 'content-type: application/json' "$SG/api/v1/query/match" -d '{
  "pattern": {
    "start": {"type": "Asset", "where": {"internet_exposed": true}},
    "steps": [
      {"edge": "HAS_FINDING", "direction": "out", "node": {"type": "Finding", "where": {"status": "open"}}},
      {"edge": "INSTANCE_OF", "direction": "out", "node": {"type": "Vulnerability", "where": {"kev": true}}}
    ],
    "limit": 100
  }}'
```

That is: internet-exposed assets with an open finding for a known-exploited vulnerability. Up to
`SECGRAPH_QUERY_MAX_DEPTH` (6) steps; `start` may instead be `{"id": "<node id>"}`; a step may give
`edges: […]`, `direction: "in" | "both"`, and a `where` on the edge's own properties. The response
says if it was truncated.

### Subgraph and shortest path

```bash
curl -H "$AUTH" -H 'content-type: application/json' "$SG/api/v1/query/subgraph" \
     -d '{"seeds": ["<id>"], "depth": 2, "max_nodes": 500}'
curl -H "$AUTH" -H 'content-type: application/json' "$SG/api/v1/query/path" \
     -d '{"source_id": "<id>", "target_id": "<id>", "max_depth": 6}'
```

`/query/path` is the shortest *relationship* path — how two things are connected at all. For how an
attacker gets from one to the other, use `/analytics/attack-paths`.

## Analytics

| Call | Answers |
|---|---|
| `GET /analytics/overview` | entry points, crown jewels at risk, expected impact with bounds, the most exposed targets |
| `GET /analytics/attack-paths?limit=10` | the best path to each crown jewel, ranked by probability × impact |
| `GET /analytics/attack-paths?target_id=<id>&limit=5` | the five most probable distinct routes to one target |
| `GET /analytics/nodes/<id>/exposure` | one entity: probability, path in, findings, controls, what it leads to |
| `GET /analytics/nodes/<id>/blast-radius` | assume it is compromised: what is reachable, which services suffer |
| `GET /analytics/remediation-priorities?by=vulnerability` | fixes ranked by the risk each removes (`by` = `finding`, `vulnerability`, `asset`) |
| `GET /analytics/choke-points` | where one control protects the most |
| `GET /analytics/detection-race` | attacker wins / detected first / contained, and expected attempts |
| `GET /analytics/parameters` | every rule, weight and formula in force |

Every response starts with `graph`: the state it was computed from (`change_seq`, `built_at`,
`ontology_version`). Probabilities come as `{"lower", "upper", "estimate", "stderr", "method"}`;
[ANALYTICS_MATH.md](ANALYTICS_MATH.md) defines each. Analytics need a credential that sees the whole
graph; a type-scoped key is refused rather than given numbers computed from half a picture.

## The change feed

```bash
curl -H "$AUTH" "$SG/api/v1/changes?after=0&limit=500&kind=node.created,node.updated&entity_type=Finding"
```

Events carry a per-tenant `seq` that only increases. Remember the last `seq` you processed and pass
it as `after`. Kinds: `node.created`, `node.updated`, `node.deleted`, `node.merged`, `edge.created`,
`edge.updated`, `edge.deleted`. The feed is kept for `SECGRAPH_CHANGE_RETENTION_DAYS` (30). Webhooks
deliver the same events ([INTEGRATION.md](INTEGRATION.md)).

## Limits

| Limit | Default | Setting |
|---|---|---|
| requests per credential per minute, per replica | 600 (burst 120) | `SECGRAPH_RATE_LIMIT_PER_MINUTE`, `_BURST` |
| records per ingest request | 50,000 | `SECGRAPH_INGEST_MAX_RECORDS` |
| ingest body | 64 MiB | `SECGRAPH_INGEST_MAX_BODY_BYTES` |
| results per page | 100 (max 1,000) | `SECGRAPH_QUERY_DEFAULT_LIMIT`, `_MAX_LIMIT` |
| traversal depth / nodes | 6 / 5,000 | `SECGRAPH_QUERY_MAX_DEPTH`, `_MAX_NODES` |

A source file larger than the record limit is split into batches by `/ingest/source/{mapping}`
automatically.

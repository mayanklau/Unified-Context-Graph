# Security

What the Security Graph protects, from whom, how, and what is left to the deployment. For reporting
a vulnerability see [../SECURITY.md](../SECURITY.md).

## What is worth protecting

The graph is a map of the organisation's weaknesses: which machines are exposed, which findings are
open, which accounts are privileged, and the most likely route to each crown jewel. Read access to
it is valuable to an attacker; write access lets one hide a route or invent one. Its agent interface
also puts text written by one party in front of another party's language model.

## Trust boundaries

```
 people ──TLS──▶ proxy ──▶ API ──▶ PostgreSQL
 products ─────▶           │  ▲
 agents ───────▶           │  └── source files (scanner output, SBOMs): untrusted content
                           ├────▶ protective plane (AgentPEP / LLM Firewall / Thoth)
                           └────▶ webhook receivers
```

## Threats and what answers them

| Threat | Answer |
|---|---|
| **Reading another tenant's graph** | Every table carries `tenant_id`; every query filters on it; a credential is bound to one tenant. The test suite runs each test in its own tenant. |
| **A credential doing more than it should** | Nine roles over thirteen permissions, checked on every route. API keys can be confined to named entity types; such a key cannot see other types through search, neighbours, paths, context or memory links, and is refused analytics outright. Out-of-scope entities return 404, not 403, so their existence is not revealed. |
| **Personal data reaching those who do not need it** | Identifiers and properties marked sensitive in the ontology are masked without `pii:read` — the `agent` and `viewer` roles do not have it. Masked identifiers become keyed pseudonyms (HMAC with the deployment secret): comparable, not reversible by hashing guesses. Masked callers cannot use search or lookup as an oracle. |
| **Stolen or guessed passwords** | PBKDF2-HMAC-SHA256, 600,000 iterations, per-password salt. Minimum 12 characters and three character classes. Five failures lock the account for 15 minutes; failed sign-ins are rate-limited per client; one error message for every failure. Disabling an account or changing its password ends its sessions on the next request. |
| **Stolen API keys** | Shown once; only a SHA-256 digest is stored. Optional expiry. Revocation is immediate. Last-used time is recorded. |
| **Forged tokens** | Local tokens are HS256 with a secret the service refuses to start without in production (32+ characters, not a known default). External tokens are RS256/ES256 only, verified against a configured public key, issuer and audience; the `none` algorithm and algorithm confusion are rejected; `platform_admin` is never accepted from a token. |
| **Tampering with history** | Entities and relationships are versioned, not overwritten. Every privileged action is in a per-tenant audit log in which each entry includes the hash of the previous one; `secgraph verify-audit` detects an altered, removed or reordered entry. (It cannot detect truncation of the newest entries by someone with database write access — export the log to the SIEM.) |
| **Poisoned source data** | Every record is validated against the ontology: unknown types, unknown properties, wrong types, out-of-range values and malformed identifiers are quarantined with a reason. Sizes are bounded (body, record count, property size, identifier length). Mapping expressions are a small declarative language with no code execution. |
| **A scanner-controlled string running as script in an analyst's browser** | The console inserts every value from the graph as text, never as markup. A strict Content-Security-Policy allows scripts only from the application's own origin — no inline script, no external hosts. A browser test plants an HTML payload in an asset name and checks it stays inert. |
| **Prompt injection through the graph** | Entity descriptions and memory notes are attacker-influenceable text. They are delivered to agents delimited as reference material; the MCP server's instructions say so; notes are redacted for secrets and size-bounded on write; and both the write and the read can be vetoed by the protective plane. This reduces the risk and does not remove it: an agent that acts on what it reads needs its own policy enforcement. |
| **Secrets leaking into shared memory** | Private keys, cloud access keys, bearer tokens, JWTs, the graph's own API keys, credentials in URLs and `password=…`-style assignments are redacted before a note is stored. |
| **The service being used to reach internal systems (SSRF)** | Webhook targets must be `http(s)`, carry no credentials, use `https` in production, and may be restricted to an allow-list (`SECGRAPH_WEBHOOK_ALLOWED_HOSTS`). Link-local addresses — cloud metadata endpoints — and multicast are always refused, checked against what the host name resolves to, at creation and again at delivery. Redirects are not followed. |
| **Forged or replayed webhooks at the receiver** | Each delivery is signed (HMAC-SHA256 over timestamp and body) with a per-subscription secret shown once. |
| **Exhaustion** | Per-credential rate limits; a request body limit enforced from the declared length and again as the body streams in; bounded traversal depth, result sizes and attack-graph size; a time budget on the what-if analytics, which also run one at a time per tenant; PostgreSQL statement timeout. |
| **Path traversal through the console's static files** | A name containing a path separator or starting with a dot is refused, and only a fixed set of file extensions is served, from the package's own directory. |
| **A compromised container** | Runs as a non-root user with a read-only root filesystem, no capabilities and `no-new-privileges`; the Kubernetes manifests meet the restricted Pod Security Standard, mount no service-account token and deny ingress by default. |
| **Supply chain** | Thirty-seven runtime packages, each pinned to a version and a SHA-256 in `requirements.lock`; the image installs with `--require-hashes` and can be built with no network at all. The console has no third-party JavaScript. Nothing is downloaded at run time. |

## What the deployment must provide

- **TLS.** The API speaks plain HTTP on the assumption that a proxy or ingress terminates TLS in
  front of it. Do not expose port 8080 directly.
- **Database security.** Network isolation, TLS to PostgreSQL where it crosses a network
  (`?sslmode=verify-full` in the URL), encryption at rest, and backups. Anyone who can write to the
  database can change the graph.
- **Secret management.** `SECGRAPH_JWT_SECRET`, the database password and the metrics token belong
  in the platform's secret store.
- **Single sign-on and MFA for people.** Local accounts have passwords only. For production, put
  the console behind the organisation's SSO proxy or issue tokens from the identity provider.
- **Audit export.** Ship the audit log and the application logs to the SIEM.

## Known limitations

Stated so that a reviewer does not have to find them:

- **Rate limits are per replica.** With N replicas a credential can make N times the configured
  rate. A shared limiter would need a shared store; enforce a global limit at the ingress if needed.
- **Webhook signing secrets are stored in the database in clear**, because the service must use
  them to sign. They are never returned by the API after creation. Protect the database accordingly.
- **Local session tokens cannot be individually revoked** before they expire (one hour by default).
  Disabling the account or changing its password ends all of its sessions at once.
- **The console keeps its token in `sessionStorage`**: it is gone when the tab closes, and it is
  readable by script running in the page — which is why the Content-Security-Policy forbids any
  script but the application's own.
- **The protective-plane hook covers context packs and memory writes**, not every read. An agent
  calling `get_entity` or `search_entities` receives graph text that has passed scope and masking
  but not the hook. Route agent traffic through AgentPEP if every tool result must be inspected.
- **Failed sign-ins are logged with the user name that was tried.**
- **No independent penetration test has been performed.** The protections above are covered by
  automated tests; that is not the same thing.

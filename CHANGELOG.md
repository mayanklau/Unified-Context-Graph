# Changelog

## 1.0.0 — 2026-09-30

First release.

**Graph**
- Ontology as data: 17 entity types, 32 relationship types and the attack semantics in one validated
  YAML file; documentation generated from it.
- Ingestion with per-record validation and quarantine; identity resolution with strong, weak,
  exclusive and derived identifiers; conflicts recorded for a steward, with pins that make decisions
  stick; merge with id redirects.
- System-versioned history for entities and relationships; `as_of` reads.
- Ten source mappings (asset and identity CSV, scanner CSV, CycloneDX, NVD, CISA KEV, EPSS, ATT&CK
  STIX, OCSF vulnerability and detection findings) and a declarative mapping language for more.
- Search, identifier lookup, neighbourhood, subgraph, shortest path and pattern match.

**Analytics**
- Attack-graph projection from the ontology's rules, with shared exploit events ("gates").
- Compromise probability as a proven lower bound, a proven upper bound and a seeded estimate
  (bit-parallel Monte Carlo, or exact enumeration on small graphs).
- K most probable attack paths with every step explained; exposure per entity; blast radius with
  business-service impact; remediation priorities by what-if recomputation, pre-ranked by an adjoint
  sensitivity pass; choke points; an absorbing-Markov detection race.

**Agents**
- MCP server (18 tools) over HTTP and stdio; token-budgeted context packs; shared memory with
  similarity- and outcome-ranked suggestions; Markdown vault export; protective-plane hook; secret
  redaction.

**Governance and operations**
- Tenants, roles, type-scoped API keys, PII masking with keyed pseudonyms, rate limits, hash-chained
  audit log, transactional change feed, signed webhooks.
- Web console with no external assets under a strict Content-Security-Policy.
- CLI, Python client, connectors for the Agentic SOC Harness.
- Alembic migrations; non-root, read-only container image that builds offline; Docker Compose with a
  TLS overlay; Kubernetes manifests; air-gap bundle; hashed lock files; Prometheus metrics; JSON logs.

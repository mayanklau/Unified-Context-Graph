# Unified Context Graph

Unified Context Graph is a modular context layer for agentic SOC, cyber risk
quantification, vulnerability management, privacy operations, agent policy
enforcement, LLM firewalling, identity, Trust SLP, and trust semantic layer
workloads.

The goal is to normalize visibility from today's cyber and AI-trust systems into
one graph-backed operating model that can absorb future controls, agents,
assets, identities, policies, obligations, evidence, risks, and incidents.

## What This Repository Contains

- A production-oriented PRD in [docs/PRD.md](docs/PRD.md)
- An architecture overview in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- A FastAPI service with modular domain packages under [src/ucg](src/ucg)
- A normalized graph ontology and in-memory repository abstraction
- Starter APIs for ingestion, graph query, risk scoring, policy enforcement,
  LLM firewall inspection, identity resolution, and trust semantic search
- Tests that validate core graph, risk, policy, and firewall behavior
- Docker, Compose, Makefile, and CI scaffolding

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn ucg.main:app --reload
```

Open:

- API: http://localhost:8000
- OpenAPI: http://localhost:8000/docs

## Example Flow

```bash
curl -X POST http://localhost:8000/v1/ingest/events \
  -H 'content-type: application/json' \
  -d '{
    "source": "agentic-soc",
    "event_type": "agent.action",
    "actor": {"id": "agent:triage-1", "type": "agent", "name": "Triage Agent"},
    "object": {"id": "asset:payments-api", "type": "service", "name": "Payments API"},
    "relationship": "observed",
    "observed_at": "2026-05-23T00:00:00Z",
    "attributes": {"severity": "high", "finding": "public exploit path"}
  }'
```

Then query the graph:

```bash
curl 'http://localhost:8000/v1/graph/nodes/asset:payments-api/context?depth=2'
```

## Design Principles

1. **Graph first, adapters second.** New products and future controls become
   connectors that emit normalized graph facts.
2. **Contracts over coupling.** Domain modules communicate through typed
   graph, policy, risk, identity, and semantic models.
3. **Explainable automation.** Agentic decisions carry evidence, policy
   decisions, risk deltas, and traceable graph context.
4. **Privacy and trust by design.** Data purpose, retention, identity, consent,
   obligation, and enforcement metadata are first-class graph concepts.
5. **Incremental production hardening.** This starter uses an in-memory
   repository for local development; the repository interface is intentionally
   isolated so Neo4j, Postgres, OpenSearch, or streaming backends can be added
   without changing API contracts.

## Repository Layout

```text
src/ucg/
  api/              FastAPI routers
  core/             Settings, errors, app lifecycle
  graph/            Ontology, repository contracts, traversal
  ingestion/        Normalized event intake
  identity/         Human, machine, workload, and agent identity mapping
  llm_firewall/     Prompt, response, and tool-call guardrails
  policy/           Agent and enterprise policy enforcement
  privacy/          Purpose, retention, data subject, and obligation models
  risk/             Cyber risk quantification and exposure scoring
  semantic_layer/   Trust semantic layer abstractions
  soc/              Agentic SOC models
  trust_slp/        Trust SLP evidence and control posture models
```

## Development

```bash
make install
make test
make lint
make run
```

## Status

This is the initial platform foundation. The next production milestones are:

- Persistent graph backend
- Connector SDK and source-specific adapters
- Streaming ingestion
- AuthN/AuthZ and tenant isolation
- Evaluation packs for LLM firewall and agent policies
- Deployment manifests for the target cloud/runtime

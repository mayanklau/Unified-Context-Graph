# Product Requirements Document: Unified Context Graph

## 1. Product Summary

Unified Context Graph (UCG) is the common context layer for an integrated cyber,
AI-trust, privacy, identity, and risk platform. It unifies visibility from
existing and future solutions into one graph of entities, relationships,
evidence, policies, risk, obligations, controls, agents, identities, prompts,
tools, incidents, vulnerabilities, and business impact.

UCG must support:

- Agentic SOC
- Cyber risk and vulnerability management
- Cyber risk quantification
- Privacy operations management
- Agent policy enforcement
- LLM firewall
- Identity for non-agentic and agentic environments
- Trust SLP
- Trust semantic layer
- Future solutions and third-party integrations

## 2. Problem Statement

Security, privacy, risk, identity, and AI governance systems produce fragmented
signals. Current workflows force analysts and agents to stitch context across
vulnerability tools, SIEM/SOAR, GRC, IAM, privacy records, data catalogs, LLM
gateways, policy engines, asset inventories, and business systems.

This creates:

- Slow triage and incident response
- Duplicate evidence collection
- Weak explainability for autonomous agent actions
- Incomplete cyber risk quantification
- Policy decisions without full context
- Poor visibility into AI and agent identities
- Privacy and regulatory obligations disconnected from technical controls
- High integration cost whenever a new solution is added

## 3. Vision

UCG becomes the shared operating memory of the platform. Any solution can write
normalized facts into the graph and read contextual intelligence back. Human
users, agents, policy engines, risk engines, and LLM guardrails all operate from
the same contextual truth.

## 4. Goals

- Create a modular, source-agnostic graph layer.
- Normalize entities and relationships across cyber, AI, privacy, identity, and
  risk domains.
- Expose APIs for ingestion, traversal, evidence lookup, policy evaluation, LLM
  firewall inspection, risk scoring, and semantic search.
- Make every automated decision explainable through graph-backed evidence.
- Allow future products to plug in as adapters without modifying the core graph
  model.
- Support multi-tenant enterprise deployment patterns.

## 5. Non-Goals For Initial Release

- Full production persistence implementation.
- Vendor-specific connector catalog.
- UI/console experience.
- Advanced graph ML or embeddings pipeline.
- Complete regulatory content library.

The initial release establishes the contracts, modular service shape, and core
graph semantics needed for these later capabilities.

## 6. Personas

- **SOC analyst:** Needs prioritized incidents, blast radius, identity context,
  evidence, and agent recommendations.
- **CISO / risk leader:** Needs quantified cyber exposure and business impact.
- **Privacy officer:** Needs data purpose, retention, data subject, and
  obligation visibility connected to systems and controls.
- **AI governance lead:** Needs agent, model, prompt, tool, and policy context.
- **IAM owner:** Needs identity relationships across humans, services, agents,
  workloads, API keys, and entitlements.
- **Autonomous security agent:** Needs policy-constrained context retrieval and
  explainable action authorization.
- **Platform engineer:** Needs stable APIs, SDKs, deployment patterns, and
  extension points.

## 7. Core Use Cases

### 7.1 Agentic SOC Context

Given an alert, UCG should retrieve related assets, identities, vulnerabilities,
data sensitivity, business services, controls, previous incidents, evidence, and
allowed agent actions.

### 7.2 Cyber Risk Quantification

Given an asset, service, or vulnerability, UCG should produce an explainable risk
score and monetary exposure inputs using exploitability, business criticality,
control posture, data sensitivity, and threat activity.

### 7.3 Vulnerability Prioritization

Given vulnerability findings, UCG should correlate exposure with internet
reachability, identities, crown-jewel assets, compensating controls, active
threats, and business impact.

### 7.4 Privacy Operations

Given a data system or process, UCG should map personal data categories, data
subjects, processing purpose, lawful basis, retention, processors, obligations,
and controls.

### 7.5 Agent Policy Enforcement

Given an agent action request, UCG should evaluate whether the actor, action,
target, context, data class, and risk level satisfy enterprise and AI governance
policies.

### 7.6 LLM Firewall

Given a prompt, response, or tool call, UCG should inspect for data exfiltration,
prompt injection, policy violations, sensitive data exposure, unsafe tool use,
and missing authorization context.

### 7.7 Agentic and Non-Agentic Identity

UCG should resolve identities across users, service accounts, workloads, agents,
models, API keys, sessions, devices, and tool credentials.

### 7.8 Trust Semantic Layer

UCG should expose a stable semantic layer so humans and agents can ask questions
over normalized trust, risk, evidence, controls, and policy context without
needing to understand vendor-specific schemas.

## 8. Functional Requirements

### 8.1 Graph Ontology

- Support typed nodes with stable IDs.
- Support typed edges with provenance and confidence.
- Include core node types: asset, identity, agent, model, tool, policy,
  vulnerability, incident, control, evidence, data set, processing activity,
  obligation, business service, risk, prompt, response, and finding.
- Include core edge types: owns, uses, accesses, observed, affects, depends_on,
  governed_by, violates, mitigates, evidences, processes, stores, invokes,
  impersonates, derived_from, linked_to, and quantifies.

### 8.2 Ingestion

- Accept normalized events through API.
- Preserve source, timestamps, attributes, and provenance.
- Upsert nodes and relationships idempotently.
- Return graph references created by ingestion.

### 8.3 Context Retrieval

- Retrieve node neighborhood by depth.
- Filter by node type, relationship type, source, confidence, and tenant.
- Return evidence and provenance for explainability.

### 8.4 Risk

- Compute explainable risk scores.
- Support severity, exploitability, exposure, business criticality, data
  sensitivity, control coverage, and threat activity inputs.
- Return score, tier, rationale, and graph evidence.

### 8.5 Policy Enforcement

- Evaluate agent or human action requests against policy rules.
- Return allow, deny, or review decisions.
- Include reasons and required evidence.
- Support high-risk action escalation.

### 8.6 LLM Firewall

- Inspect prompt, response, and tool call text.
- Detect suspicious instruction override, credential leakage, secrets,
  sensitive data, destructive tool use, and policy bypass attempts.
- Return decision, findings, and recommended controls.

### 8.7 Identity

- Resolve graph context for humans, services, workloads, and agents.
- Link credentials, sessions, tools, and delegated authorities.
- Distinguish autonomous agent identity from the human or service principal that
  owns it.

### 8.8 Privacy Operations

- Model data purpose, lawful basis, retention, subject category, processor, and
  obligation.
- Link obligations to assets, controls, and evidence.

### 8.9 Semantic Layer

- Provide domain concepts and canonical labels.
- Support natural-language-to-context translation in later releases.
- Return explainable graph facts instead of opaque answers.

## 9. Non-Functional Requirements

- **Modularity:** Domain modules must be independently extensible.
- **Security:** APIs should be ready for auth, tenant isolation, and audit.
- **Reliability:** Graph writes must be idempotent.
- **Explainability:** Decisions must include evidence references.
- **Performance:** Initial traversal target is sub-second for small graphs;
  production backend must support enterprise-scale indexing.
- **Observability:** Service exposes health endpoint and structured logs.
- **Portability:** Runs locally with Python and in containerized deployments.
- **Testability:** Core modules are unit tested without external services.

## 10. Data Model

Every graph node includes:

- `id`
- `type`
- `name`
- `tenant_id`
- `attributes`
- `sources`
- `created_at`
- `updated_at`

Every graph edge includes:

- `id`
- `type`
- `source_id`
- `target_id`
- `tenant_id`
- `confidence`
- `attributes`
- `provenance`
- `observed_at`

## 11. APIs

- `GET /health`
- `POST /v1/ingest/events`
- `GET /v1/graph/nodes/{node_id}`
- `GET /v1/graph/nodes/{node_id}/context`
- `POST /v1/risk/score`
- `POST /v1/policy/evaluate`
- `POST /v1/llm-firewall/inspect`
- `GET /v1/identity/{identity_id}/context`
- `POST /v1/semantic/query`

## 12. Success Metrics

- Time to onboard a new solution adapter.
- Percentage of agent actions with explainable policy decisions.
- Reduction in manual context gathering for SOC investigations.
- Number of risk scores backed by graph evidence.
- Query latency for graph context retrieval.
- Coverage of identity types across agentic and non-agentic systems.
- Number of privacy obligations linked to technical assets and controls.

## 13. Release Plan

### Milestone 1: Platform Spine

- PRD and architecture docs.
- FastAPI service.
- In-memory graph repository.
- Core ontology and domain models.
- Ingestion, graph query, risk, policy, firewall, identity, and semantic APIs.
- Unit tests and CI.

### Milestone 2: Persistence and Connectors

- Neo4j or Postgres graph backend.
- Connector SDK.
- SIEM, vulnerability, IAM, CMDB, data catalog, LLM gateway adapters.
- Tenant and auth model.

### Milestone 3: Production Intelligence

- Semantic query translation.
- Risk quantification calibration.
- Policy authoring and simulation.
- Agent decision audit trails.
- LLM firewall evaluation packs.

### Milestone 4: Enterprise Scale

- Streaming ingestion.
- HA deployment.
- Multi-region support.
- Governance workflows.
- UI and reporting layer.

## 14. Key Risks

- Ontology may become too broad without strict extension governance.
- Graph backend choice can constrain traversal and scale characteristics.
- Risk quantification requires customer-specific calibration.
- LLM firewall efficacy depends on continuous evaluation and red-team data.
- Agent authorization requires strong identity binding and auditability.

## 15. Open Decisions

- Production graph store: Neo4j, Postgres + Apache AGE, or hybrid.
- Embedding/vector store for semantic layer.
- Policy language: custom rules, Cedar, OPA/Rego, or hybrid.
- Event streaming stack: Kafka, Redpanda, Kinesis, or cloud-native queues.
- Multi-tenant isolation level: logical, database, or deployment boundary.

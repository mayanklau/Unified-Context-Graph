# Product Requirements Document: Unified Context Graph

## 1. Product Summary

Unified Context Graph (UCG) is the common context graph layer for a cyber,
AI-trust, privacy, identity, data protection, and risk platform. It unifies
visibility from current and future solutions into one extensible graph of
entities, relationships, evidence, policies, risks, obligations, controls,
agents, identities, prompts, tool calls, vulnerabilities, incidents, data flows,
and business impact.

UCG must support:

- Agentic SOC
- Cyber risk and vulnerability management
- Cyber risk quantification
- Privacy operations management
- Agent policy enforcement
- LLM firewall
- Identity for non-agentic and agentic environments
- Trust DLP
- Trust semantic layer
- Future first-party and third-party solutions

## 2. Problem Statement

Security, privacy, risk, identity, data protection, and AI governance systems
produce fragmented signals. Current workflows force analysts, risk teams,
privacy teams, and autonomous agents to reconstruct context across vulnerability
tools, SIEM/SOAR, EDR, CSPM, GRC, IAM, PAM, privacy records, data catalogs, DLP,
LLM gateways, model registries, policy engines, asset inventories, and business
systems.

This creates:

- Slow triage and incident response
- Duplicate evidence collection
- Weak explainability for autonomous agent actions
- Incomplete cyber risk quantification
- Policy decisions without full context
- Poor visibility into AI and agent identities
- Poor visibility into sensitive data movement
- Privacy and regulatory obligations disconnected from technical controls
- DLP decisions disconnected from prompts, tools, identities, and business risk
- High integration cost whenever a new solution is added

## 3. Vision

UCG becomes the shared operating memory of the platform. Any solution can write
normalized facts into the graph and read contextual intelligence back. Human
users, agents, policy engines, risk engines, LLM firewalls, Trust DLP controls,
privacy workflows, and SOC workflows all operate from the same contextual truth.

## 4. Goals

- Create a modular, source-agnostic graph layer.
- Normalize entities and relationships across cyber, AI, privacy, identity,
  Trust DLP, and risk domains.
- Expose APIs for ingestion, traversal, evidence lookup, policy evaluation, LLM
  firewall inspection, risk scoring, DLP context, identity context, and semantic
  search.
- Make every automated decision explainable through graph-backed evidence.
- Allow future products to plug in as adapters without modifying the core graph
  model.
- Support multi-tenant enterprise deployment patterns.
- Support both human-led workflows and autonomous agent workflows.
- Provide a stable semantic layer over normalized trust, risk, policy, privacy,
  identity, and data protection concepts.

## 5. Non-Goals For Initial Release

- Full production persistence implementation.
- Complete vendor-specific connector catalog.
- Full UI/console experience.
- Advanced graph ML or embeddings pipeline.
- Complete regulatory content library.
- Full policy authoring language.
- Full Trust DLP enforcement engine.

The initial release establishes contracts, modular service shape, graph
semantics, and starter engines needed for later production capabilities.

## 6. Personas

- **SOC analyst:** Needs prioritized incidents, blast radius, identity context,
  evidence, and agent recommendations.
- **CISO / risk leader:** Needs quantified cyber exposure and business impact.
- **Vulnerability manager:** Needs remediation priority based on exploitability,
  exposure, asset criticality, identity reachability, and compensating controls.
- **Privacy officer:** Needs data purpose, retention, data subject, lawful basis,
  processor, and obligation visibility connected to systems and controls.
- **Trust DLP owner:** Needs sensitive data movement, exfiltration risk, DLP
  policy, data flow, actor, prompt, response, tool, and control context.
- **AI governance lead:** Needs agent, model, prompt, response, tool, policy,
  evaluation, and decision context.
- **IAM owner:** Needs identity relationships across humans, services, agents,
  workloads, API keys, sessions, devices, and entitlements.
- **Autonomous security agent:** Needs policy-constrained context retrieval and
  explainable action authorization.
- **Platform engineer:** Needs stable APIs, SDKs, deployment patterns, and
  extension points.

## 7. Core Use Cases

### 7.1 Agentic SOC Context

Given an alert, UCG should retrieve related assets, identities, vulnerabilities,
data sensitivity, business services, controls, previous incidents, evidence,
Trust DLP signals, LLM traces, and allowed agent actions.

### 7.2 Cyber Risk Quantification

Given an asset, service, vulnerability, identity, data set, or business process,
UCG should produce an explainable risk score and exposure inputs using
exploitability, business criticality, control posture, sensitive data, threat
activity, identity reachability, and known incidents.

### 7.3 Vulnerability Prioritization

Given vulnerability findings, UCG should correlate exposure with internet
reachability, identities, crown-jewel assets, compensating controls, sensitive
data, active threats, business services, and exception history.

### 7.4 Privacy Operations

Given a data system or processing activity, UCG should map personal data
categories, data subjects, processing purpose, lawful basis, retention,
processors, sub-processors, transfer regions, obligations, evidence, and
technical controls.

### 7.5 Trust DLP

Given a data movement event, prompt, response, file, tool call, or identity
action, UCG should determine what data is involved, who or what moved it, where
it is going, what purpose applies, which policies govern it, which obligations
apply, which controls are active, and whether the action should be allowed,
redacted, blocked, quarantined, reviewed, or escalated.

### 7.6 Agent Policy Enforcement

Given an agent action request, UCG should evaluate whether actor, action,
target, context, delegated authority, data class, policy, and risk level satisfy
enterprise and AI governance policies.

### 7.7 LLM Firewall

Given a prompt, response, or tool call, UCG should inspect for data exfiltration,
prompt injection, policy violations, sensitive data exposure, unsafe tool use,
missing authorization context, and Trust DLP violations.

### 7.8 Agentic And Non-Agentic Identity

UCG should resolve identities across users, service accounts, workloads, agents,
models, API keys, sessions, devices, tool credentials, delegated authorities,
and ownership chains.

### 7.9 Trust Semantic Layer

UCG should expose a stable semantic layer so humans and agents can ask questions
over normalized trust, risk, evidence, controls, identity, privacy, policy, and
data protection context without needing to understand vendor-specific schemas.

### 7.10 Future Solution Integration

Given a new solution, UCG should allow the platform team to add an adapter that
emits normalized graph facts while preserving source provenance and avoiding
core graph rewrites.

## 8. Feature Requirements

### 8.1 Graph Ontology

- Support typed nodes with stable IDs.
- Support typed edges with provenance and confidence.
- Include core node types: asset, identity, agent, model, tool, policy,
  vulnerability, incident, control, evidence, data set, data flow, processing
  activity, obligation, business service, risk, prompt, response, finding,
  threat actor, attack technique, connector, tenant, and workflow.
- Include core edge types: owns, uses, accesses, observed, affects, depends_on,
  governed_by, violates, mitigates, evidences, processes, stores, invokes,
  impersonates, derived_from, linked_to, quantifies, transfers_to, classifies,
  delegates_to, runs_on, exposed_to, protected_by, and requires.
- Preserve source provenance, confidence, timestamps, and attributes.
- Support extension governance so domain teams can add concepts without schema
  drift.

### 8.2 Ingestion

- Accept normalized events through API.
- Preserve source, timestamps, attributes, source record ID, and provenance.
- Upsert nodes and relationships idempotently.
- Support future batch ingestion, streaming ingestion, replay, dead-letter
  queues, and connector health.
- Return graph references created by ingestion.

### 8.3 Context Retrieval

- Retrieve node neighborhood by depth.
- Filter by node type, relationship type, source, tenant, confidence, time
  range, and sensitivity.
- Return evidence and provenance for explainability.
- Support purpose-bound retrieval for agents and privacy-sensitive data.
- Support future graph paths, shortest path, blast radius, and impact queries.

### 8.4 Agentic SOC

- Correlate alert context across assets, identities, vulnerabilities, controls,
  incidents, findings, DLP events, and business services.
- Return investigation context packages for humans and agents.
- Track recommended actions, approved actions, denied actions, and evidence.
- Support future playbook execution and case management integration.

### 8.5 Cyber Risk Quantification

- Compute explainable risk scores.
- Support severity, exploitability, exposure, business criticality, data
  sensitivity, identity reachability, control coverage, and threat activity.
- Return score, tier, rationale, and graph evidence.
- Support future monetary loss exposure, scenario modeling, control ROI, and
  board-level risk reporting.

### 8.6 Vulnerability And Exposure Management

- Link vulnerabilities to affected assets, software, services, owners, internet
  exposure, exploit availability, controls, exceptions, and remediation work.
- Prioritize vulnerabilities based on graph-derived business and threat context.
- Support exception governance and compensating control evidence.

### 8.7 Policy Enforcement

- Evaluate agent or human action requests against policy rules.
- Return allow, deny, or review decisions.
- Include reasons, required controls, and graph evidence.
- Support high-risk action escalation.
- Support policy simulation before enabling enforcement.
- Support future policy engines such as Cedar, OPA/Rego, or hybrid rules.

### 8.8 LLM Firewall

- Inspect prompt, response, and tool call text.
- Detect suspicious instruction override, credential leakage, secrets,
  sensitive data, destructive tool use, and policy bypass attempts.
- Use graph context to determine actor, target, data class, tool permission,
  business purpose, and Trust DLP posture.
- Return decision, findings, recommended controls, and trace references.
- Support future red-team evaluation packs and adaptive detection.

### 8.9 Identity

- Resolve graph context for humans, services, workloads, agents, models,
  credentials, sessions, and devices.
- Link credentials, delegated authorities, tools, owners, entitlements, and
  runtime sessions.
- Distinguish autonomous agent identity from the human or service principal that
  owns it.
- Support least privilege analysis and identity blast radius.

### 8.10 Privacy Operations

- Model data purpose, lawful basis, retention, subject category, processor,
  transfer region, and obligation.
- Link obligations to assets, controls, evidence, data sets, and data flows.
- Support DSAR, RoPA, DPIA, deletion, retention, and consent workflows in later
  releases.

### 8.11 Trust DLP

- Model sensitive data categories, data sets, data flows, prompts, responses,
  files, tool calls, destinations, policies, controls, and obligations.
- Determine whether data movement is consistent with purpose, identity, policy,
  consent, business context, and risk posture.
- Support Trust DLP outcomes: allow, redact, block, quarantine, review,
  escalate, and require additional authorization.
- Connect DLP findings to SOC incidents, risk scoring, privacy obligations, LLM
  firewall decisions, and agent policy decisions.
- Support future inline enforcement, asynchronous discovery, endpoint/network
  DLP ingestion, SaaS DLP ingestion, and model/prompt DLP.

### 8.12 Trust Semantic Layer

- Provide domain concepts and canonical labels.
- Support natural-language-to-context translation in later releases.
- Return explainable graph facts instead of opaque answers.
- Provide stable vocabulary for agents, analysts, executives, and integrations.

### 8.13 Connector And Adapter Framework

- Define a connector contract for source ingestion.
- Map source records to normalized nodes, edges, and evidence.
- Track connector source, version, health, and coverage.
- Support future connector catalog for SIEM, EDR, CNAPP, CSPM, IAM, PAM, GRC,
  CMDB, vulnerability scanners, privacy tools, DLP, data catalogs, LLM gateways,
  model registries, ticketing systems, and business systems.

## 9. Non-Functional Requirements

- **Modularity:** Domain modules must be independently extensible.
- **Security:** APIs must be ready for auth, tenant isolation, scoped access,
  secret handling, and audit.
- **Reliability:** Graph writes must be idempotent.
- **Explainability:** Decisions must include evidence references and rationale.
- **Performance:** Initial traversal target is sub-second for small graphs;
  production backend must support enterprise-scale indexing and traversal.
- **Observability:** Service exposes health endpoint and structured logs.
- **Portability:** Runs locally with Python and in containerized deployments.
- **Testability:** Core modules are unit tested without external services.
- **Governance:** Ontology and connector changes must be reviewable and versioned.
- **Privacy:** Retrieval and processing must support purpose limitation and data
  minimization.

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

Important graph domains:

- **Security:** assets, vulnerabilities, findings, incidents, controls,
  evidence, attack techniques, threat activity.
- **Identity:** humans, agents, service accounts, workloads, sessions, devices,
  credentials, entitlements, delegated authorities.
- **AI trust:** models, prompts, responses, tools, tool calls, policies,
  evaluations, guardrails.
- **Privacy:** data sets, personal data categories, subject categories,
  purposes, lawful basis, retention, processors, obligations.
- **Trust DLP:** sensitive data categories, files, data flows, destinations,
  DLP findings, redaction decisions, exfiltration paths, policy boundaries.
- **Risk:** risk scores, scenarios, business services, impact, likelihood,
  exposure, control posture.

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

Future APIs:

- `POST /v1/connectors/events:batch`
- `GET /v1/graph/paths`
- `POST /v1/trust-dlp/evaluate`
- `POST /v1/agents/actions/evaluate`
- `POST /v1/privacy/obligations/evaluate`
- `POST /v1/risk/scenarios`
- `GET /v1/evidence/{evidence_id}`
- `POST /v1/semantic/ask`

## 12. Success Metrics

- Time to onboard a new solution adapter.
- Percentage of agent actions with explainable policy decisions.
- Reduction in manual context gathering for SOC investigations.
- Number of risk scores backed by graph evidence.
- Query latency for graph context retrieval.
- Coverage of identity types across agentic and non-agentic systems.
- Number of privacy obligations linked to technical assets and controls.
- Number of Trust DLP decisions backed by identity, purpose, and policy context.
- False positive and false negative rate for LLM firewall and DLP detections.
- Percentage of high-risk vulnerabilities with business impact context.

## 13. Release Plan

### Milestone 1: Platform Spine

- PRD and architecture docs.
- FastAPI service.
- In-memory graph repository.
- Core ontology and domain models.
- Ingestion, graph query, risk, policy, firewall, identity, and semantic APIs.
- Unit tests and CI.
- Trust DLP domain model foundation.

### Milestone 2: Persistence And Connectors

- Neo4j, Postgres graph, or hybrid backend.
- Connector SDK.
- SIEM, vulnerability, IAM, CMDB, data catalog, DLP, LLM gateway, and model
  registry adapters.
- Tenant and auth model.
- Audit event model.

### Milestone 3: Production Intelligence

- Semantic query translation.
- Risk quantification calibration.
- Policy authoring and simulation.
- Agent decision audit trails.
- LLM firewall evaluation packs.
- Trust DLP policy evaluation and data movement scoring.

### Milestone 4: Enterprise Scale

- Streaming ingestion.
- HA deployment.
- Multi-region support.
- Governance workflows.
- UI and reporting layer.
- Connector marketplace and lifecycle management.

## 14. Key Risks

- Ontology may become too broad without strict extension governance.
- Graph backend choice can constrain traversal and scale characteristics.
- Risk quantification requires customer-specific calibration.
- LLM firewall efficacy depends on continuous evaluation and red-team data.
- Trust DLP accuracy depends on classification quality and destination context.
- Agent authorization requires strong identity binding and auditability.
- Privacy-sensitive graph retrieval must avoid overexposing data to agents.

## 15. Open Decisions

- Production graph store: Neo4j, Postgres + Apache AGE, or hybrid.
- Embedding/vector store for semantic layer.
- Policy language: custom rules, Cedar, OPA/Rego, or hybrid.
- Event streaming stack: Kafka, Redpanda, Kinesis, or cloud-native queues.
- Multi-tenant isolation level: logical, database, or deployment boundary.
- Trust DLP enforcement point: API gateway, endpoint agent, proxy, LLM gateway,
  SaaS integration, or all of the above.
- Sensitive data classifier strategy: deterministic, ML-based, vendor source,
  customer-defined, or hybrid.

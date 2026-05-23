from pydantic import BaseModel, Field


class Capability(BaseModel):
    name: str
    description: str
    priority: str = "future"
    dependencies: list[str] = Field(default_factory=list)


class CapabilityArea(BaseModel):
    name: str
    description: str
    capabilities: list[Capability]


CAPABILITY_ROADMAP: list[CapabilityArea] = [
    CapabilityArea(
        name="Graph Platform Foundation",
        description="Core graph, provenance, governance, persistence, and quality capabilities.",
        capabilities=[
            Capability(
                name="Persistent graph backend",
                description=(
                    "Add Neo4j, Postgres graph, or hybrid storage behind the "
                    "repository interface."
                ),
                priority="near-term",
            ),
            Capability(
                name="Temporal graph history",
                description="Support point-in-time investigations, lineage, and regulatory proof.",
            ),
            Capability(
                name="Entity resolution",
                description=(
                    "Deduplicate and merge assets, identities, data sets, "
                    "vulnerabilities, and agents."
                ),
            ),
            Capability(
                name="Graph quality scoring",
                description=(
                    "Score freshness, completeness, provenance, and confidence "
                    "for graph facts."
                ),
            ),
        ],
    ),
    CapabilityArea(
        name="Connector Ecosystem",
        description=(
            "SDK, marketplace, and ingestion patterns for first-party and "
            "third-party systems."
        ),
        capabilities=[
            Capability(
                name="Connector SDK",
                description="Provide mapping templates, validation, replay, and contract tests.",
                priority="near-term",
            ),
            Capability(
                name="Security connectors",
                description=(
                    "Integrate SIEM, SOAR, EDR, XDR, NDR, CNAPP, CSPM, and "
                    "vulnerability sources."
                ),
            ),
            Capability(
                name="AI and data connectors",
                description=(
                    "Integrate LLM gateways, model registries, DLP, data "
                    "catalogs, and vector stores."
                ),
            ),
            Capability(
                name="Business context connectors",
                description=(
                    "Import ownership, revenue, process criticality, geography, "
                    "and service tiers."
                ),
            ),
        ],
    ),
    CapabilityArea(
        name="Agentic SOC",
        description=(
            "Investigation, triage, attack paths, evidence packs, and safe "
            "autonomous response."
        ),
        capabilities=[
            Capability(
                name="Alert-to-graph correlation",
                description=(
                    "Build case context from alerts, assets, identities, "
                    "findings, and controls."
                ),
                priority="near-term",
            ),
            Capability(
                name="Attack path reconstruction",
                description="Link identity, network, vulnerability, data, and business paths.",
            ),
            Capability(
                name="Agent investigation workspace",
                description="Preserve evidence, reasoning traces, approvals, and response actions.",
            ),
        ],
    ),
    CapabilityArea(
        name="Cyber Risk Quantification",
        description="Financial exposure, scenario analysis, portfolio risk, and control ROI.",
        capabilities=[
            Capability(
                name="Scenario library",
                description=(
                    "Model ransomware, data exfiltration, cloud breach, agent "
                    "misuse, and supply-chain events."
                ),
            ),
            Capability(
                name="Financial exposure modeling",
                description=(
                    "Estimate frequency, magnitude, and business impact from "
                    "graph context."
                ),
            ),
            Capability(
                name="Control ROI",
                description=(
                    "Compare remediation cost, risk reduction, and compensating "
                    "control evidence."
                ),
            ),
        ],
    ),
    CapabilityArea(
        name="Trust DLP",
        description="Sensitive data movement, policy, purpose, identity, and enforcement context.",
        capabilities=[
            Capability(
                name="Trust-aware DLP evaluation",
                description=(
                    "Decide allow, redact, block, quarantine, review, or "
                    "escalate using graph context."
                ),
                priority="near-term",
            ),
            Capability(
                name="Prompt and response DLP",
                description="Detect and govern sensitive data in LLM and agent workflows.",
            ),
            Capability(
                name="Data flow lineage",
                description=(
                    "Track sensitive data movement across systems, agents, "
                    "regions, and vendors."
                ),
            ),
        ],
    ),
    CapabilityArea(
        name="LLM Firewall And AI Security",
        description="Prompt, response, retrieval, tool-use, model, and agent security controls.",
        capabilities=[
            Capability(
                name="Tool-use authorization",
                description=(
                    "Evaluate agent tool calls against identity, policy, risk, "
                    "and data context."
                ),
            ),
            Capability(
                name="RAG guardrails",
                description=(
                    "Apply retrieval permissions, purpose limits, and sensitive "
                    "data controls."
                ),
            ),
            Capability(
                name="AI red-team packs",
                description=(
                    "Continuously test prompt injection, jailbreaks, data "
                    "leakage, and unsafe actions."
                ),
            ),
        ],
    ),
    CapabilityArea(
        name="Privacy Operations",
        description="RoPA, DPIA, DSAR, retention, consent, transfer, and obligation workflows.",
        capabilities=[
            Capability(
                name="Obligation graph",
                description=(
                    "Map regulation, geography, contract, data category, "
                    "system, and control obligations."
                ),
            ),
            Capability(
                name="Retention and deletion verification",
                description="Use graph evidence to prove retention and deletion controls.",
            ),
            Capability(
                name="Privacy incident correlation",
                description="Connect privacy incidents to SOC, DLP, identity, and risk context.",
            ),
        ],
    ),
    CapabilityArea(
        name="Trust Semantic Layer",
        description=(
            "Canonical vocabulary, natural-language querying, citations, and "
            "role-aware answers."
        ),
        capabilities=[
            Capability(
                name="Natural-language graph questions",
                description="Translate questions into graph traversals with cited evidence.",
            ),
            Capability(
                name="Ontology mapping",
                description=(
                    "Map vendor schemas to canonical trust, risk, policy, "
                    "privacy, and identity concepts."
                ),
            ),
            Capability(
                name="Agent retrieval contracts",
                description="Define safe, purpose-bound context packages for autonomous agents.",
            ),
        ],
    ),
]

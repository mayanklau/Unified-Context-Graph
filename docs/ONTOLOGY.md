# Ontology reference — security-graph-core 1.0.0

> Generated from the ontology file by `secgraph ontology docs`. Do not edit by hand: change the YAML
> and regenerate. A test fails if this file and the packaged ontology disagree.

Core ontology joining the cyber plane (assets, identities, exposure, controls, detections), the business plane (services, data) and the AI plane (agents, models, tools) in one graph.

Fingerprint: `e718b0598a3ae7d4ad0f2e204eced3a0e7c6067e606f6df10de3170dddb5ada7`

## Node types

| Type | Plane | What it is |
|---|---|---|
| [Asset](#asset) | cyber | Anything that computes or routes — server, workstation, container, cloud resource, network or OT device. |
| [Identity](#identity) | cyber | A human, service, machine or agent account, or a group of them. |
| [Software](#software) | cyber | A software component at a specific version (package, product, firmware). |
| [Vulnerability](#vulnerability) | cyber | A publicly or privately identified weakness (CVE or advisory). |
| [Finding](#finding) | cyber | One occurrence of a vulnerability or misconfiguration on one asset, with its own lifecycle. |
| [Control](#control) | cyber | A deployed security control instance and how well it works. |
| [Alert](#alert) | cyber | A detection raised by the SIEM, EDR or another sensor. |
| [Incident](#incident) | cyber | A case grouping alerts into one investigation. |
| [Indicator](#indicator) | threat | An observable associated with malicious activity (IP, domain, URL, file hash). |
| [Technique](#technique) | threat | A MITRE ATT&CK (or ATLAS) technique. |
| [ThreatActor](#threatactor) | threat | A tracked adversary group or campaign. |
| [BusinessService](#businessservice) | business | A business capability the organisation must keep running. |
| [DataStore](#datastore) | business | A place data lives — database, bucket, share, vector store or knowledge base. |
| [NetworkSegment](#networksegment) | cyber | A network zone or subnet. In attack maths it is a network position an attacker can hold. |
| [AIAgent](#aiagent) | ai | An AI agent or agentic workflow that acts on behalf of the organisation. |
| [AIModel](#aimodel) | ai | A language or ML model that agents call. |
| [Tool](#tool) | ai | A tool or API an agent can invoke (for example an MCP tool). |

### Asset

Anything that computes or routes — server, workstation, container, cloud resource, network or OT device.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `cloud_id` | strong, exclusive | none | Cloud provider resource id / ARN |
| `serial` | strong, exclusive | upper | Hardware serial number |
| `agent_id` | strong, exclusive | lower | EDR / management agent id |
| `asset_id` | strong, exclusive | lower | CMDB or asset-inventory record id |
| `fqdn` | strong, exclusive | fqdn | Fully qualified domain name |
| `mac` | strong | mac | Network interface MAC address |
| `hostname` | weak | hostname | Short host name — weak because prod and dev hosts can share it Derived from `fqdn` when absent. |
| `ip` | lookup only | ip | IP address — searchable but never used to merge (DHCP, NAT) |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `asset_type` | one of `server`, `workstation`, `laptop`, `mobile`, `virtual_machine`, `container`, `kubernetes_cluster`, `cloud_resource`, `network_device`, `firewall`, `load_balancer`, `database_server`, `application`, `iot`, `ot`, `other` |  |
| `os` | string |  |
| `os_version` | string |  |
| `environment` | one of `production`, `staging`, `development`, `test`, `dr`, `unknown` |  |
| `criticality` | integer (≥ 1, ≤ 5) | Business criticality, 5 is highest |
| `crown_jewel` | boolean | Explicitly designated high-value asset |
| `internet_exposed` | boolean | Reachable from the internet |
| `owner` | string |  |
| `location` | string |  |
| `status` | one of `active`, `decommissioned`, `quarantined`, `unknown` |  |

Other properties are accepted and stored as given.

### Identity

A human, service, machine or agent account, or a group of them.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `sid` | strong, exclusive | upper | Directory security identifier |
| `upn` | strong, exclusive | email | User principal name Personal data (masked without `pii:read`). |
| `account` | strong | lower | Account name, e.g. domain\user or a service-account name |
| `email` | strong | email | Mail address Personal data (masked without `pii:read`). |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `display_name` | string | Personal data (masked without `pii:read`). |
| `identity_type` | one of `human`, `service`, `machine`, `agent`, `group` |  |
| `privileged` | boolean | Holds administrative rights |
| `mfa_enabled` | boolean |  |
| `status` | one of `active`, `disabled`, `locked`, `unknown` |  |
| `department` | string |  |
| `last_logon` | datetime |  |

Other properties are accepted and stored as given.

### Software

A software component at a specific version (package, product, firmware).

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `purl` | strong, exclusive | purl | Package URL |
| `cpe` | strong | cpe | CPE 2.3 name |
| `software_key` | strong | lower | vendor:product:version when no purl/CPE exists |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `version` | string |  |
| `vendor` | string |  |
| `ecosystem` | string |  |
| `end_of_life` | boolean |  |
| `license` | string |  |

Other properties are accepted and stored as given.

### Vulnerability

A publicly or privately identified weakness (CVE or advisory).

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `cve` | strong, exclusive | cve |  |
| `vuln_id` | strong | upper | Non-CVE advisory id (GHSA, vendor advisory, internal) |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `title` | string |  |
| `description` | string |  |
| `cvss_score` | number (≥ 0, ≤ 10) |  |
| `cvss_vector` | string |  |
| `attack_vector` | one of `network`, `adjacent`, `local`, `physical` |  |
| `epss` | number (≥ 0, ≤ 1) | EPSS probability |
| `epss_percentile` | number (≥ 0, ≤ 1) |  |
| `kev` | boolean | Listed in a known-exploited catalogue (CISA KEV / CERT-In) |
| `kev_date_added` | datetime |  |
| `ransomware_use` | boolean |  |
| `exploit_available` | boolean |  |
| `cwe` | string_list |  |
| `published` | datetime |  |

Other properties are accepted and stored as given.

### Finding

One occurrence of a vulnerability or misconfiguration on one asset, with its own lifecycle.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `finding_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `title` | string |  |
| `status` | one of `open`, `in_progress`, `reopened`, `risk_accepted`, `resolved`, `false_positive` |  |
| `severity` | one of `critical`, `high`, `medium`, `low`, `info` |  |
| `scanner` | string |  |
| `port` | integer (≥ 0, ≤ 65535) |  |
| `protocol` | string |  |
| `first_detected` | datetime |  |
| `last_detected` | datetime |  |
| `due_date` | datetime |  |
| `exception_until` | datetime | Risk acceptance expiry |
| `exception_reason` | string |  |
| `ticket_ref` | string |  |

Other properties are accepted and stored as given.

### Control

A deployed security control instance and how well it works.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `control_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `control_type` | one of `waf`, `network_ips`, `virtual_patching`, `segmentation`, `firewall`, `edr`, `ndr`, `siem_detection`, `deception`, `mfa`, `pam`, `jit_access`, `credential_guard`, `encryption_at_rest`, `dlp`, `email_security`, `patch_management`, `app_allowlisting`, `backup`, `llm_firewall`, `semantic_firewall`, `agent_policy_enforcement`, `tool_sandboxing`, `human_in_the_loop`, `other` | Required. |
| `effectiveness` | number (≥ 0, ≤ 1) | Measured or assessed effectiveness |
| `status` | one of `active`, `degraded`, `inactive`, `planned` |  |
| `vendor` | string |  |
| `framework_refs` | string_list | Control framework references, e.g. RBI-CSF 4.2, ISO27001 A.8.8 |

Other properties are accepted and stored as given.

### Alert

A detection raised by the SIEM, EDR or another sensor.

Expires when not re-observed for 365 days.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `alert_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `title` | string |  |
| `severity` | one of `critical`, `high`, `medium`, `low`, `info` |  |
| `status` | one of `new`, `triaged`, `investigating`, `closed` |  |
| `disposition` | one of `true_positive`, `false_positive`, `benign`, `unknown` |  |
| `rule` | string |  |
| `source_product` | string |  |
| `event_time` | datetime |  |
| `description` | string |  |

Other properties are accepted and stored as given.

### Incident

A case grouping alerts into one investigation.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `incident_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `title` | string |  |
| `severity` | one of `critical`, `high`, `medium`, `low`, `info` |  |
| `status` | one of `open`, `contained`, `eradicated`, `closed` |  |
| `disposition` | one of `true_positive`, `false_positive`, `benign`, `unknown` |  |
| `opened_at` | datetime |  |
| `closed_at` | datetime |  |
| `summary` | string |  |

Other properties are accepted and stored as given.

### Indicator

An observable associated with malicious activity (IP, domain, URL, file hash).

Expires when not re-observed for 180 days.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `indicator` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `indicator_type` | one of `ip`, `domain`, `url`, `hash`, `email`, `other` |  |
| `reputation` | one of `malicious`, `suspicious`, `benign`, `unknown` |  |
| `source` | string |  |

Other properties are accepted and stored as given.

### Technique

A MITRE ATT&CK (or ATLAS) technique.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `attack_id` | strong, exclusive | attack_id |  |
| `stix_id` | strong | lower | STIX object id — lets STIX relationships join |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `tactics` | string_list |  |
| `platforms` | string_list |  |
| `description` | string |  |

Other properties are accepted and stored as given.

### ThreatActor

A tracked adversary group or campaign.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `actor_key` | strong, exclusive | lower |  |
| `stix_id` | strong | lower | STIX object id — lets STIX relationships join |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `aliases` | string_list |  |
| `motivation` | string |  |
| `sophistication` | one of `low`, `medium`, `high`, `advanced` |  |
| `description` | string |  |

Other properties are accepted and stored as given.

### BusinessService

A business capability the organisation must keep running.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `service_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `criticality` | integer (≥ 1, ≤ 5) |  |
| `owner` | string |  |
| `rto_hours` | number (≥ 0) |  |
| `regulatory_tags` | string_list | e.g. RBI, DPDPA, CERT-In, PCI-DSS |
| `description` | string |  |

Other properties are accepted and stored as given.

### DataStore

A place data lives — database, bucket, share, vector store or knowledge base.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `datastore_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `store_type` | one of `database`, `object_storage`, `file_share`, `data_lake`, `vector_store`, `knowledge_base`, `saas`, `other` |  |
| `classification` | one of `public`, `internal`, `confidential`, `restricted` |  |
| `contains_pii` | boolean |  |
| `pii_categories` | string_list |  |
| `record_count` | integer (≥ 0) |  |
| `criticality` | integer (≥ 1, ≤ 5) |  |
| `crown_jewel` | boolean |  |
| `owner` | string |  |

Other properties are accepted and stored as given.

### NetworkSegment

A network zone or subnet. In attack maths it is a network position an attacker can hold.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `segment_key` | strong, exclusive | lower |  |
| `cidr` | strong | cidr |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `zone` | one of `internet`, `dmz`, `internal`, `restricted`, `management`, `ot`, `cloud`, `partner` |  |

Other properties are accepted and stored as given.

### AIAgent

An AI agent or agentic workflow that acts on behalf of the organisation.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `agent_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `purpose` | string |  |
| `framework` | string |  |
| `autonomy_level` | one of `assistive`, `supervised`, `autonomous` |  |
| `status` | one of `active`, `disabled`, `experimental` |  |
| `owner` | string |  |
| `criticality` | integer (≥ 1, ≤ 5) |  |
| `crown_jewel` | boolean |  |

Other properties are accepted and stored as given.

### AIModel

A language or ML model that agents call.

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `model_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `provider` | string |  |
| `version` | string |  |
| `deployment` | one of `on_prem`, `private_cloud`, `public_api` |  |
| `sovereign` | boolean | Runs entirely inside the organisation's jurisdiction and control |
| `fine_tuned` | boolean |  |

Other properties are accepted and stored as given.

### Tool

A tool or API an agent can invoke (for example an MCP tool).

**Identifiers** (in matching priority)

| Kind | Strength | Normalised as | Notes |
|---|---|---|---|
| `tool_key` | strong, exclusive | lower |  |

**Properties**

| Property | Type | Notes |
|---|---|---|
| `name` | string |  |
| `description` | string |  |
| `protocol` | one of `mcp`, `http`, `grpc`, `native`, `other` |  |
| `risk_tier` | one of `read_only`, `low`, `medium`, `high`, `critical` |  |
| `side_effects` | boolean |  |

Other properties are accepted and stored as given.

## Edge types

| Edge | From | To | Meaning | Expires |
|---|---|---|---|---|
| `RUNS` | Asset | Software | The asset has this software installed or running. | 90 d |
| `HAS_FINDING` | Asset | Finding | The finding was detected on this asset. | — |
| `INSTANCE_OF` | Finding | Vulnerability | The finding is an occurrence of this vulnerability. | — |
| `AFFECTS` | Vulnerability | Software | The vulnerability affects this software version. | — |
| `CONNECTS_TO` | Asset | Asset | The source asset can open a connection to the target asset (observed flow or allowed path). | 30 d |
| `IN_SEGMENT` | Asset | NetworkSegment | The asset sits in this network segment. | — |
| `ROUTES_TO` | NetworkSegment | NetworkSegment | Traffic is permitted from the source segment to the target segment. | — |
| `HAS_ACCESS` | Identity | Asset, DataStore, Tool | The identity is authorised on the target. | — |
| `HAS_SESSION` | Asset | Identity | Credential material for the identity is present on the asset (logon session, cached credential, token). | 14 d |
| `MEMBER_OF` | Identity | Identity | The identity inherits the rights of the group. | — |
| `OWNS` | Identity | Asset, DataStore, BusinessService, AIAgent | Accountable owner (no attacker movement implied). | — |
| `HOSTS` | Asset | DataStore | The data store runs on, or is served by, this asset. | — |
| `SUPPORTS` | Asset, DataStore, AIAgent | BusinessService | The business service needs this component to operate. | — |
| `DEPENDS_ON` | BusinessService | BusinessService, Asset, DataStore, AIAgent | The source service needs the target to operate. | — |
| `PROTECTS` | Control | Asset, Identity, DataStore, NetworkSegment, AIAgent, Tool | The control covers the target. | — |
| `MITIGATES` | Control | Finding, Vulnerability, Technique | The control compensates for a specific finding, vulnerability or technique. | — |
| `TRIGGERED_ON` | Alert | Asset, Identity, AIAgent, DataStore | The alert fired on this entity. | — |
| `INDICATES` | Alert | Technique | The alert maps to this technique. | — |
| `OBSERVED` | Alert | Indicator | The alert contained this indicator. | — |
| `PART_OF` | Alert | Incident | The alert belongs to this incident. | — |
| `INVOLVES` | Incident | Asset, Identity, AIAgent, DataStore | The incident involves this entity. | — |
| `ATTRIBUTED_TO` | Incident | ThreatActor | The incident is attributed to this actor. | — |
| `USES` | ThreatActor | Technique | The actor is known to use this technique. | — |
| `EXPLOITS` | ThreatActor | Vulnerability | The actor is known to exploit this vulnerability. | — |
| `RUNS_ON` | AIAgent, AIModel | Asset | The agent or model is hosted on this asset. | — |
| `USES_MODEL` | AIAgent | AIModel | The agent calls this model. | — |
| `CAN_INVOKE` | AIAgent | Tool | The agent is permitted to call this tool. | — |
| `ACTS_AS` | AIAgent | Identity | The agent operates with this identity's rights. | — |
| `READS_FROM` | AIAgent | DataStore | The agent retrieves content from this data store (retrieval source, knowledge base). | — |
| `WRITES_TO` | AIAgent | DataStore | The agent can modify this data store. | — |
| `TOOL_TARGETS` | Tool | Asset, DataStore | The tool acts on this asset or data store. | — |
| `DELEGATES_TO` | AIAgent | AIAgent | The agent hands work to another agent. | — |

### Edge properties

| Edge | Property | Type | Notes |
|---|---|---|---|
| `RUNS` | `install_path` | string |  |
| `AFFECTS` | `version_range` | string |  |
| `CONNECTS_TO` | `port` | integer (≥ 0, ≤ 65535) |  |
| `CONNECTS_TO` | `protocol` | string |  |
| `CONNECTS_TO` | `service` | string |  |
| `ROUTES_TO` | `ports` | string |  |
| `ROUTES_TO` | `policy_ref` | string |  |
| `HAS_ACCESS` | `privilege` | one of `read`, `write`, `admin` |  |
| `HAS_ACCESS` | `via` | string | How access is exercised — rdp, ssh, db role, api |
| `HAS_SESSION` | `session_type` | one of `interactive`, `service`, `cached`, `token` |  |
| `TOOL_TARGETS` | `effect` | one of `read`, `write`, `execute` |  |

## Attack semantics

How the graph becomes an attack graph. See [ANALYTICS_MATH.md](ANALYTICS_MATH.md) for the mathematics.

**States an attacker can hold:** Asset, Identity, DataStore, AIAgent, Tool, NetworkSegment

### Entry rules

| Rule | Applies to | Probability | Reduced by | Enabled |
|---|---|---|---|---|
| `internet_exposed_asset` | Asset where internet_exposed=True | exploitability of the destination (never below 0.02) | waf, network_ips, virtual_patching | yes |
| `internet_segment` | NetworkSegment where zone=internet | 1 | — | yes |
| `phishing` | Identity where identity_type=human | 0.05 | mfa, email_security | no |

### Transition rules

| Rule | Edge | Attacker moves | Probability | Reduced by (control on) | What it models |
|---|---|---|---|---|---|
| `network_position` | `IN_SEGMENT` | Asset → NetworkSegment | 1 | — | A foothold on an asset gives a network position in its segment. |
| `routed_access` | `ROUTES_TO` | NetworkSegment → NetworkSegment | 1 | segmentation (destination) | A position in one segment reaches every segment it is allowed to route to. |
| `segment_exploit` | `IN_SEGMENT` | NetworkSegment → Asset | exploitability of the destination | network_ips, virtual_patching, waf (destination) | From a position in the segment, the attacker exploits an open finding on an asset in it. |
| `lateral_exploit` | `CONNECTS_TO` | Asset → Asset | exploitability of the destination | network_ips, virtual_patching, waf, segmentation (destination) | From one asset, the attacker exploits an open finding on an asset it can connect to. |
| `credential_theft` | `HAS_SESSION` | Asset → Identity | 0.6 | credential_guard, edr, pam (either) | The attacker harvests credential material present on a compromised asset. |
| `use_access` | `HAS_ACCESS` | Identity → Asset/DataStore/Tool | by `privilege`: admin 0.95, write 0.8, read 0.6; otherwise 0.6 | mfa, pam, jit_access (either) | The attacker uses a compromised identity's authorisations. |
| `group_membership` | `MEMBER_OF` | Identity → Identity | 1 | — | A compromised identity holds the rights of its groups. |
| `data_on_host` | `HOSTS` | Asset → DataStore | 0.9 | encryption_at_rest, dlp (destination) | A foothold on a host reaches the data stores it serves. |
| `agent_host_takeover` | `RUNS_ON` | Asset → AIAgent/AIModel | 0.9 | tool_sandboxing, edr (either) | A foothold on the host running an agent gives control of the agent. |
| `indirect_prompt_injection` | `READS_FROM` | DataStore → AIAgent | 0.3 | llm_firewall, semantic_firewall, agent_policy_enforcement (destination) | Content planted in a store the agent reads from steers the agent. |
| `agent_data_read` | `READS_FROM` | AIAgent → DataStore | 0.9 | agent_policy_enforcement, dlp (either) | A controlled agent reads what it is allowed to retrieve. |
| `agent_data_write` | `WRITES_TO` | AIAgent → DataStore | 0.9 | agent_policy_enforcement, human_in_the_loop (either) | A controlled agent modifies the stores it can write to. |
| `agent_identity_abuse` | `ACTS_AS` | AIAgent → Identity | 0.9 | agent_policy_enforcement, jit_access (either) | A controlled agent exercises the rights of the identity it acts as. |
| `tool_invocation` | `CAN_INVOKE` | AIAgent → Tool | 0.8 | agent_policy_enforcement, human_in_the_loop, tool_sandboxing (either) | A controlled agent invokes a tool it is permitted to call. |
| `tool_effect` | `TOOL_TARGETS` | Tool → Asset/DataStore | by `effect`: execute 0.9, write 0.7, read 0.4; otherwise 0.4 | tool_sandboxing, human_in_the_loop (either) | A misused tool acts on the assets and data it targets. |
| `agent_delegation` | `DELEGATES_TO` | AIAgent → AIAgent | 0.5 | agent_policy_enforcement, llm_firewall (destination) | A controlled agent passes attacker-influenced work to another agent. |

### Crown jewels

| Rule | Applies to | Impact |
|---|---|---|
| `crown_jewel_asset` | Asset where crown_jewel=True | by `criticality`: 1→1, 2→2, 3→4, 4→8, 5→16; otherwise 8 |
| `critical_asset` | Asset where criticality={'gte': 5} | 16 |
| `crown_jewel_data` | DataStore where crown_jewel=True | by `criticality`: 1→1, 2→2, 3→4, 4→8, 5→16; otherwise 12 |
| `restricted_data` | DataStore where classification=restricted | 12 |
| `personal_data` | DataStore where contains_pii=True | 10 |
| `privileged_identity` | Identity where privileged=True | 8 |
| `crown_jewel_agent` | AIAgent where crown_jewel=True | by `criticality`: 1→1, 2→2, 3→4, 4→8, 5→16; otherwise 8 |

### Exploitability parameters

| Parameter | Value |
|---|---|
| Finding statuses counted as open | open, in_progress, reopened, risk_accepted |
| Known-exploited floor | 0.9 |
| EPSS weight | 1 |
| CVSS vector weight | 0.6 |
| CVSS base-score weight | 0.3 |
| Default when nothing is known | 0.05 |
| Severity fallback (no linked vulnerability) | critical 0.5, high 0.3, medium 0.15, low 0.05, info 0 |
| Remotely exploitable attack vectors | network, adjacent |
| Unknown vector treated as remote | yes |
| Probability cap | 0.99 |

### Control parameters

| Parameter | Value |
|---|---|
| Default effectiveness by type | waf 0.6, network_ips 0.5, virtual_patching 0.8, segmentation 0.7, firewall 0.5, mfa 0.9, pam 0.7, jit_access 0.6, credential_guard 0.7, edr 0.5, ndr 0.4, siem_detection 0.4, deception 0.3, encryption_at_rest 0.7, dlp 0.4, email_security 0.6, patch_management 0.5, app_allowlisting 0.6, llm_firewall 0.6, semantic_firewall 0.6, agent_policy_enforcement 0.7, tool_sandboxing 0.6, human_in_the_loop 0.8 |
| Fallback effectiveness | 0.5 |
| Degraded control factor | 0.5 |
| Maximum combined reduction | 0.99 |
| Detective control types | edr, ndr, siem_detection, deception |
| Base detection per attempt | 0.02 |
| Detection weight | 0.3 |

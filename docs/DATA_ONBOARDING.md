# Getting data in

## The short version

```bash
secgraph mappings                                          # what this installation can read
secgraph ingest assets.csv --mapping assets_csv            # a source file, through a mapping
secgraph ingest sbom.cdx.json --mapping cyclonedx --param asset_fqdn=web-01.corp.example
secgraph ingest batch.json                                 # a canonical batch, no mapping
```

or over HTTP, with a credential that holds `graph:write` (roles `ingest`, `steward`, `admin`):

```bash
curl -H "X-API-Key: $KEY" --data-binary @assets.csv "$SG/api/v1/ingest/source/assets_csv"
curl -H "X-API-Key: $KEY" --data-binary @sbom.json  "$SG/api/v1/ingest/source/cyclonedx?param.asset_fqdn=web-01.corp.example"
curl -H "X-API-Key: $KEY" -H 'content-type: application/json' -d @batch.json "$SG/api/v1/ingest"
```

or from the console: **Data quality → Load data**.

Loading is idempotent. Loading the same file twice changes nothing but `last_seen`. Load order does
not matter: an edge that names an entity not yet seen creates a placeholder ("stub") that the real
record fills in later.

## Shipped mappings

| Mapping | Reads | Source name |
|---|---|---|
| `assets_csv` | asset inventory / CMDB export | `cmdb` |
| `identities_csv` | directory export (accounts, groups, memberships) | `directory` |
| `vuln_findings_csv` | vulnerability scanner export | `scanner` |
| `cyclonedx` | CycloneDX JSON SBOM | `sbom` |
| `nvd_cve` | NVD CVE API 2.0 JSON | `nvd` |
| `cisa_kev` | CISA Known Exploited Vulnerabilities catalogue | `kev` |
| `epss_csv` | FIRST EPSS scores | `epss` |
| `attack_stix` | MITRE ATT&CK STIX 2.1 bundle | `mitre-attack` |
| `ocsf_vulnerability_finding` | OCSF class 2002 | `ocsf` |
| `ocsf_detection_finding` | OCSF class 2004 | `ocsf` |

Each mapping file in `secgraph/ingest/mappings/` starts with a comment listing the columns or
fields it reads, and `secgraph/demo/sources/` has a small sample of every format.

In an air-gapped environment, NVD, KEV, EPSS and ATT&CK are files carried across on the usual
transfer path and loaded with the same commands. Nothing is downloaded by the service.

## The canonical format

Every mapping produces this, and you can post it directly:

```json
{
  "source": "cmdb",
  "observed_at": "2026-09-30T06:00:00Z",
  "nodes": [
    {"type": "Asset", "ref": "a1",
     "identifiers": {"fqdn": "web-01.corp.example", "ip": ["10.0.0.5"], "serial": "VMW-7F3A"},
     "properties": {"os": "Ubuntu", "criticality": 4, "internet_exposed": true}}
  ],
  "edges": [
    {"type": "HAS_FINDING",
     "source": {"ref": "a1"},
     "target": {"type": "Finding", "identifiers": {"finding_key": "scan:123"}}},
    {"type": "CONNECTS_TO", "key": "tcp/5432",
     "source": {"ref": "a1"},
     "target": {"type": "Asset", "identifiers": {"fqdn": "db-01.corp.example"}},
     "properties": {"port": 5432, "protocol": "tcp"}}
  ]
}
```

- `source` names the system the data came from; it is recorded on every property it sets.
- An edge endpoint is one of: `{"ref": …}` (a node in this batch), `{"id": …}` (a graph id), or
  `{"type": …, "identifiers": {…}}` (resolved through the identity spine).
- `key` distinguishes parallel relationships of one type between the same two entities.
- `"op": "delete"` on a node or edge retracts it (history is kept).
- `observed_at` (batch or record) is when the source saw the fact. A record older than what the
  graph already holds does not overwrite newer values.

The response reports, for nodes and edges, how many were created, updated, unchanged, deleted and
quarantined, plus conflicts raised and placeholders created.

## Writing a mapping for a new source

A mapping is a YAML file. Put it in a directory, set `SECGRAPH_MAPPINGS_DIR` to that directory, and
it appears in `secgraph mappings` and the console. A mapping with the same name as a shipped one
replaces it. Mappings are checked against the ontology at start-up: an unknown type, identifier or
property stops the process with a message naming the file and the field.

```yaml
# config/mappings/example_cmdb.yaml — one JSON document: {"result": [{…}, …]}
mapping:
  name: example_cmdb
  description: Example CMDB REST export
  format: json            # json | jsonl | csv
  source: cmdb
  records: "$.result"     # where the list of records is
emit:
  - node:
      type: Asset
      ref: asset
      identifiers:
        asset_id: "$.sys_id"
        fqdn: "$.fqdn"
        ip: {path: "$.ip_address", transform: split_comma}
      properties:
        name: "$.name"
        os: "$.os"
        environment: {path: "$.used_for", map: {Production: production, Test: test}, default: unknown}
        criticality: {path: "$.business_criticality", transform: int}
        owner: {coalesce: ["$.owned_by.display_value", "$.support_group.display_value"]}
  - node:
      when: "$.business_service"
      type: BusinessService
      ref: service
      identifiers:
        service_key: "$.business_service"
      properties:
        name: "$.business_service"
  - edge:
      type: SUPPORTS
      source: {ref: asset}
      target: {ref: service}
```

### Expressions

| Written as | Means |
|---|---|
| `"$.a.b[0].c"` | a path into the current record; `[*]` fans out over a list, `[?k=v]` filters one |
| `"$^.a"` | a path into the enclosing record, inside `foreach` |
| `"$$.a"` | a path into the document root |
| `"@name"` | a parameter given with the ingest call (`--param name=value` or `?param.name=value`) |
| anything else | a literal |
| `{path: …, default: …, map: {…}, transform: …}` | a path with post-processing: `map` translates the values it lists and passes others through unchanged; `default` applies when the field is empty |
| `{concat: [a, b, …]}` | joined; empty if any part is empty |
| `{coalesce: [a, b, …]}` | the first non-empty |
| `{literal: "$.not-a-path"}` | a literal that looks like a path |

Transforms: `lower`, `upper`, `strip`, `string`, `bool`, `int`, `float`, `first`, `last`, `unique`,
`basename`, `split_comma`, `split_semicolon`, `split_space`, `percent_to_fraction`.

Conditions (`when:`): an expression (true when non-empty), or `{eq: [a, b]}`, `{ne: [a, b]}`,
`{in: [a, [...]]}`, `{startswith: [a, "x"]}`, `{exists: a}`, `{not: c}`, `{all: [...]}`,
`{any: [...]}`.

`foreach: <expression>` with a nested `emit:` repeats a block for each element of a list inside a
record. `mapping.parameters` documents accepted parameters; `required_parameters` makes them
mandatory.

Test a mapping the way the shipped ones are tested (`tests/test_mappings.py`): a small fixture file,
an assertion on what it produced, and an assertion that nothing was quarantined.

## How records become entities

Each node type declares its identifiers in the ontology:

| Kind | Example (Asset) | Meaning |
|---|---|---|
| strong | `serial`, `cloud_id`, `agent_id`, `asset_id`, `fqdn`, `mac` | two records sharing the value are the same entity |
| exclusive | all of the above except `mac` | an entity has one value; two different values mean two different entities |
| weak | `hostname` | evidence: enough to match when exactly one compatible candidate exists |
| not used for matching | `ip` | recorded and searchable, but never decides identity — addresses are reused |
| derived | `hostname` from `fqdn` | computed, so a scanner that only knows the short name still matches |

Identifiers are normalised before comparison (`WEB-01.Corp.Example.` and `web-01.corp.example` are
the same; so are `00-1A-2B-3C-4D-5E` and `001a.2b3c.4d5e`).

What happens to a record:

1. **Strong identifiers match one entity** → the record updates it and adds any new identifiers.
2. **Nothing matches** → a new entity.
3. **Only weak identifiers, one candidate** → it updates that candidate.
4. **Only weak identifiers, several candidates** → the record goes to a single placeholder entity
   and a conflict is raised. It is not attached to a guess.
5. **Strong identifiers point at two different entities**, or an exclusive identifier disagrees →
   nothing is merged; a conflict is raised.

### Conflicts

`GET /api/v1/conflicts`, or **Data quality → Identity conflicts** in the console. A steward either

- **resolves** it by naming the entity the records belong to — the decision is stored as a pin, so
  the same records resolve the same way from then on; or
- **merges** two entities that are one (`POST /api/v1/nodes/merge`) — relationships, identifiers
  and history move to the survivor, and the old id keeps working as a redirect; or
- **dismisses** it: these really are two things.

### Property conflicts between sources

`SECGRAPH_SOURCE_PRIORITY=cmdb,edr,scanner` — for any property, a source earlier in the list is not
overwritten by one later in the list. Sources not listed rank below those that are. Each property
remembers which source set it.

## Quarantine

A record that fails validation — unknown type, a property of the wrong type, an enum value the
ontology does not list, an identifier that does not parse — is stored with its reason and the rest
of the batch is applied. `GET /api/v1/quarantine`, or **Data quality → Quarantine**. After fixing
the cause (usually the mapping or the ontology), replay the records; or discard them.

## Staleness and retention

- A node or edge type can declare `ttl_days` in the ontology. The worker retires elements that no
  source has reported for that long (for example, `HAS_SESSION` relationships). History is kept.
- `SECGRAPH_HISTORY_RETENTION_DAYS` prunes old versions (0 keeps everything);
  `SECGRAPH_CHANGE_RETENTION_DAYS` prunes the change feed.

## Extending the ontology

Copy `secgraph/ontology/core.ontology.yaml`, edit it, set `SECGRAPH_ONTOLOGY_FILE`, and check it:

```bash
secgraph ontology validate my.ontology.yaml
secgraph ontology docs my.ontology.yaml > ONTOLOGY.md
```

Adding a type, property, identifier or attack rule needs no code and no migration. Removing or
renaming something that existing data uses leaves that data in place but unreachable through the
removed name; plan such changes as a data migration.

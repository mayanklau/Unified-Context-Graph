# Site configuration

Things an installation adds without changing the code:

| What | Where | Setting |
|---|---|---|
| Source mappings for your own systems | `config/mappings/*.yaml` | `SECGRAPH_MAPPINGS_DIR=/path/to/config/mappings` |
| Your own ontology (extra types, properties, attack rules, calibrated weights) | a copy of `secgraph/ontology/core.ontology.yaml` | `SECGRAPH_ONTOLOGY_FILE=/path/to/your.ontology.yaml` |
| Everything else | environment variables — see `.env.example` | |

`mappings/example_cmdb.yaml` is a worked example; `docs/DATA_ONBOARDING.md` explains it.

In a container, mount this directory read-only and set the two variables, for example in
`docker-compose.yml`:

```yaml
  api:
    volumes:
      - ./config:/etc/secgraph:ro
    environment:
      SECGRAPH_MAPPINGS_DIR: /etc/secgraph/mappings
```

# Contributing

## Set up

```bash
make install        # .venv, pinned and hash-checked dependencies, the project in editable mode
make check          # lint, type-check, tests — what CI runs, minus PostgreSQL and the image
```

Python 3.11 or newer. `make help` lists every task.

## The rules that keep this maintainable

1. **The ontology is the model.** A new entity type, property, identifier, relationship or attack
   rule is a change to `secgraph/ontology/core.ontology.yaml`, not to Python. If code needs to name a
   specific type, it should be reading a binding from the ontology instead
   (`attack_semantics.bindings`). After changing the ontology: `make docs` (a test fails if
   `docs/ONTOLOGY.md` is stale).
2. **A new source is a mapping.** `secgraph/ingest/mappings/<name>.yaml`, a sample in
   `secgraph/demo/sources/`, and a test in `tests/test_mappings.py` that asserts what it produced and
   that nothing was quarantined.
3. **Nothing above `secgraph/store` writes SQL**, and every query filters on `tenant_id`.
4. **Schema changes are migrations.** Change `secgraph/store/models.py`, then add a revision under
   `secgraph/store/migrations/versions/`. `tests/test_migrations.py` fails if the models and the
   migrations disagree.
5. **Every number must be explainable.** An analytic that returns a probability returns what it was
   computed from. Anything sampled is seeded. New maths comes with a test against brute force or a
   closed form, and a section in `docs/ANALYTICS_MATH.md`.
6. **Graph content is untrusted text.** In the console it goes through `h()` as a text node — never
   `innerHTML`. For agents it is delimited as data.
7. **Every route checks a permission**, returns 404 for what the caller may not see, and goes
   through `Viewer` on the way out so that scope and masking apply.
8. **No network at run time, no new services.** The product runs air-gapped on PostgreSQL alone. A
   dependency that phones home, or a feature that needs another stateful service, needs a very good
   reason.
9. **Errors are typed** (`secgraph/errors.py`) and messages name the field and the fix.

## Tests

```bash
make test                                   # SQLite
make test-postgres SECGRAPH_TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost/secgraph_test
.venv/bin/playwright install chromium && make test-ui
make coverage
```

Each test gets its own tenant, so tests do not see each other's data and can run against a shared
database. Concurrency tests (`-m postgres`) only run on PostgreSQL.

## Dependencies

Runtime dependencies are listed in `pyproject.toml` and locked with hashes in `requirements.lock`
(`requirements-dev.lock` adds the development tools). After changing them: `make lock`, run the
tests, and commit both lock files. Keep the runtime list short: every package is one more thing to
carry across an air gap and one more thing to patch.

## Commits and releases

Small commits with a subject that says what changed and a body that says why. For a release: update
`CHANGELOG.md`, bump the version in `pyproject.toml`, `secgraph/__init__.py`, the `Dockerfile` label,
`Makefile`, `docker-compose.yml` and `deploy/kubernetes` (image tag and migration Job name), tag, and
build the air-gap bundle from the tag.

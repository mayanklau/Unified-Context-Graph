# Security Graph — common tasks. `make help` lists them.

PYTHON  ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
VERSION := 1.0.0
IMAGE   ?= security-graph:$(VERSION)
DEV_DB  ?= sqlite:///./secgraph.db
DEV_ENV := SECGRAPH_DATABASE_URL=$(DEV_DB) SECGRAPH_LOG_JSON=false

.DEFAULT_GOAL := help
.PHONY: help install demo dev test test-postgres test-ui coverage lint format typecheck check \
        docs lock image up up-demo down logs airgap-bundle bench clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(BIN)/secgraph: pyproject.toml requirements-dev.lock
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --require-hashes -r requirements-dev.lock
	$(BIN)/pip install --quiet --no-deps -e .
	@touch $(BIN)/secgraph

lock: ## Re-resolve requirements.lock and requirements-dev.lock (needs uv)
	uv pip compile pyproject.toml --universal --generate-hashes --python-version 3.11 -o requirements.lock
	uv pip compile pyproject.toml --extra dev --extra ui-test --universal --generate-hashes --python-version 3.11 -o requirements-dev.lock

install: $(BIN)/secgraph ## Create .venv and install the project with development tools

demo: install ## No Docker: SQLite, the demonstration estate, console on http://127.0.0.1:8080 (admin / see output)
	$(DEV_ENV) $(BIN)/secgraph migrate
	$(DEV_ENV) $(BIN)/secgraph seed-demo
	@echo
	@echo "Console: http://127.0.0.1:8080   username: admin   password: Meridian-Demo-2026"
	@echo
	$(DEV_ENV) SECGRAPH_BOOTSTRAP_ADMIN_PASSWORD=Meridian-Demo-2026 $(BIN)/secgraph serve --host 127.0.0.1

dev: install ## Run the API against a local SQLite file, empty graph
	$(DEV_ENV) $(BIN)/secgraph migrate
	$(DEV_ENV) SECGRAPH_BOOTSTRAP_ADMIN_PASSWORD=Meridian-Demo-2026 $(BIN)/secgraph serve --host 127.0.0.1

test: install ## Unit and integration tests on SQLite (browser tests run when Chromium is available)
	$(BIN)/python -m pytest

test-postgres: install ## The same suite on PostgreSQL: make test-postgres SECGRAPH_TEST_DATABASE_URL=postgresql+psycopg://...
	@test -n "$(SECGRAPH_TEST_DATABASE_URL)" || { echo "set SECGRAPH_TEST_DATABASE_URL"; exit 2; }
	SECGRAPH_TEST_DATABASE_URL=$(SECGRAPH_TEST_DATABASE_URL) $(BIN)/python -m pytest

test-ui: install ## Browser tests only (first: .venv/bin/playwright install chromium)
	$(BIN)/python -m pytest -m ui

coverage: install ## Tests with a coverage report
	$(BIN)/python -m pytest --cov --cov-report=term-missing:skip-covered

lint: install ## Ruff lint and format check
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format: install ## Apply formatting and safe lint fixes
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

typecheck: install ## mypy
	$(BIN)/mypy secgraph

check: lint typecheck test ## Everything CI runs, except PostgreSQL and the image build

docs: install ## Regenerate docs/ONTOLOGY.md and docs/openapi.json from the code
	$(BIN)/secgraph ontology docs > docs/ONTOLOGY.md
	$(BIN)/python scripts/export_openapi.py docs/openapi.json

image: ## Build the container image
	docker build -t $(IMAGE) .

up: ## Docker: start PostgreSQL, API and worker; create the first admin
	./scripts/quickstart.sh

up-demo: ## Docker: the same, with the demonstration estate loaded
	./scripts/quickstart.sh --demo

down: ## Docker: stop the stack (data is kept)
	docker compose down

logs: ## Docker: follow the logs
	docker compose logs -f --tail=100

airgap-bundle: ## Build an offline installation bundle in dist/
	./scripts/airgap-bundle.sh

bench: install ## Measure ingestion and analytics on a synthetic estate
	$(BIN)/python scripts/benchmark.py

clean: ## Remove build output and caches (not .env, not data)
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

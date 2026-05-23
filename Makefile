.PHONY: install run test lint docker-build

install:
	pip install -e ".[dev]"

run:
	uvicorn ucg.main:app --reload

test:
	pytest

lint:
	ruff check src tests

docker-build:
	docker build -t unified-context-graph:local .

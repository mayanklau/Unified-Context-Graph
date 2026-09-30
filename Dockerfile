# syntax=docker/dockerfile:1
#
# Security Graph — one image for the API, the worker and the CLI.
#
#   docker build -t security-graph:1.0.0 .
#
# Air-gapped build: put the wheels in ./wheelhouse first (scripts/airgap-bundle.sh
# does this) and the build installs from there without touching the network.
# Behind a registry mirror, pass --build-arg PYTHON_IMAGE=<mirror>/python:3.11-slim.

ARG PYTHON_IMAGE=python:3.11-slim

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY requirements.lock ./
COPY wheelhouse/ /wheelhouse/

# Dependencies first, so they are cached until the lock file changes. Every
# package is pinned and hash-checked.
RUN python -m venv /opt/secgraph \
 && if ls /wheelhouse/*.whl >/dev/null 2>&1; then \
      /opt/secgraph/bin/pip install --no-index --find-links /wheelhouse --require-hashes -r requirements.lock; \
    else \
      /opt/secgraph/bin/pip install --require-hashes -r requirements.lock; \
    fi

COPY pyproject.toml README.md LICENSE ./
COPY secgraph/ ./secgraph/
# The base image ships setuptools and wheel, so the project builds offline too.
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /dist . \
 && /opt/secgraph/bin/pip install --no-deps --no-index /dist/*.whl \
 && /opt/secgraph/bin/python -m compileall -q /opt/secgraph/lib

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="security-graph" \
      org.opencontainers.image.description="Sovereign, on-prem security graph with explainable attack-path maths" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="1.0.0"

ENV PATH=/opt/secgraph/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECGRAPH_ENVIRONMENT=production

RUN groupadd --system --gid 10001 secgraph \
 && useradd --system --uid 10001 --gid secgraph --home-dir /nonexistent --shell /usr/sbin/nologin secgraph

COPY --from=build /opt/secgraph /opt/secgraph

USER 10001:10001
WORKDIR /tmp
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=4 \
  CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]

ENTRYPOINT ["secgraph"]
CMD ["serve"]

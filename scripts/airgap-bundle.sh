#!/usr/bin/env bash
# Build everything needed to install Security Graph on a network with no internet access.
#
# Run this on a connected machine with Docker. It produces
#   dist/security-graph-<version>-airgap.tar.gz
# containing the container images (application + PostgreSQL), the compose files,
# the Python wheels (for installing without Docker) and install.sh.
#
# On the air-gapped host:
#   tar xzf security-graph-<version>-airgap.tar.gz && cd security-graph-<version>-airgap
#   bash install.sh            # loads the images and starts the stack
#
# Options (environment):
#   PYTHON_IMAGE    base image to build from   (default python:3.11-slim)
#   POSTGRES_IMAGE  database image to include  (default postgres:16-alpine)
#   SKIP_POSTGRES=1 leave PostgreSQL out (you run your own)
#   PIP_DOWNLOAD_ON_HOST=1  download wheels with the host's pip instead of inside the base image
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.11-slim}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
IMAGE="security-graph:${VERSION}"
NAME="security-graph-${VERSION}-airgap"
OUT="dist/${NAME}"

command -v docker >/dev/null 2>&1 || { echo "Docker is required to build the bundle." >&2; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT/images" "$OUT/wheels"

echo "==> Downloading Python wheels (Linux x86_64, CPython 3.11)"
find wheelhouse -name '*.whl' -delete
if [ "${PIP_DOWNLOAD_ON_HOST:-0}" = 1 ]; then
  python3 -m pip download --quiet --require-hashes -r requirements.lock --dest wheelhouse \
    --only-binary=:all: --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 \
    --python-version 3.11 --implementation cp
else
  docker run --rm -v "$PWD:/src" -w /src "$PYTHON_IMAGE" \
    pip download --quiet --disable-pip-version-check --require-hashes -r requirements.lock --dest wheelhouse
fi

echo "==> Building ${IMAGE} from the downloaded wheels (no network during the build)"
docker build --network none --build-arg "PYTHON_IMAGE=${PYTHON_IMAGE}" -t "$IMAGE" .

echo "==> Saving images"
docker save "$IMAGE" | gzip > "$OUT/images/security-graph.tar.gz"
if [ "${SKIP_POSTGRES:-0}" != 1 ]; then
  docker image inspect "$POSTGRES_IMAGE" >/dev/null 2>&1 || docker pull "$POSTGRES_IMAGE"
  docker save "$POSTGRES_IMAGE" | gzip > "$OUT/images/postgres.tar.gz"
fi

echo "==> Collecting wheels for installation without Docker"
cp wheelhouse/*.whl "$OUT/wheels/"
docker run --rm --network none -v "$PWD:/src:ro" -v "$PWD/$OUT/wheels:/out" -w /tmp --user 0 --entrypoint sh "$PYTHON_IMAGE" -c \
  'cp -r /src/secgraph /src/pyproject.toml /src/README.md /src/LICENSE /tmp/ && pip wheel --quiet --no-deps --no-build-isolation --wheel-dir /out /tmp'
cp requirements.lock "$OUT/wheels/"

echo "==> Adding deployment files"
cp docker-compose.yml .env.example LICENSE README.md "$OUT/"
mkdir -p "$OUT/deploy" "$OUT/scripts" "$OUT/docs"
cp -r deploy/compose deploy/nginx deploy/kubernetes "$OUT/deploy/"
cp scripts/quickstart.sh "$OUT/scripts/"
cp docs/*.md "$OUT/docs/" 2>/dev/null || true
# The images are loaded, not built, on the air-gapped host.
sed -i.bak '/^  build:/,/^      PYTHON_IMAGE:.*/d' "$OUT/docker-compose.yml" && rm -f "$OUT/docker-compose.yml.bak"
sed -i.bak 's/docker compose up -d --build --wait/docker compose up -d --wait/' "$OUT/scripts/quickstart.sh" && rm -f "$OUT/scripts/quickstart.sh.bak"
sed -i.bak 's/then `docker compose up -d --build`/then `docker compose up -d`/' "$OUT/docker-compose.yml" && rm -f "$OUT/docker-compose.yml.bak"

cat > "$OUT/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Install Security Graph from this bundle. No network access is needed.
#   bash install.sh          load the images, start the stack, create the first admin
#   bash install.sh --demo   also load the demonstration estate
set -euo pipefail
cd "$(dirname "$0")"
for image in images/*.tar.gz; do
  echo "Loading $image"
  gunzip -c "$image" | docker load
done
exec bash scripts/quickstart.sh "$@"
INSTALL
chmod +x "$OUT/install.sh" "$OUT/scripts/quickstart.sh"

cat > "$OUT/INSTALL-WITHOUT-DOCKER.txt" <<NOTE
Installing without Docker (Python 3.11 on Linux x86_64, PostgreSQL 14+ reachable):

  python3.11 -m venv /opt/secgraph
  /opt/secgraph/bin/pip install --no-index --find-links wheels --require-hashes -r wheels/requirements.lock
  /opt/secgraph/bin/pip install --no-index --no-deps wheels/security_graph-${VERSION}-py3-none-any.whl

  export SECGRAPH_ENVIRONMENT=production
  export SECGRAPH_DATABASE_URL=postgresql+psycopg://secgraph:<password>@<host>:5432/secgraph
  export SECGRAPH_JWT_SECRET=<32+ random characters>
  /opt/secgraph/bin/secgraph migrate
  /opt/secgraph/bin/secgraph doctor
  /opt/secgraph/bin/secgraph users create admin --roles admin --password-stdin
  /opt/secgraph/bin/secgraph serve      # and, as a second process:  secgraph worker

docs/OPERATIONS.md has the systemd units and the rest.
NOTE

( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
tar -C dist -czf "dist/${NAME}.tar.gz" "$NAME"
rm -rf "$OUT"
echo
echo "Bundle: dist/${NAME}.tar.gz ($(du -h "dist/${NAME}.tar.gz" | cut -f1))"
sha256sum "dist/${NAME}.tar.gz"

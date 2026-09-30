#!/usr/bin/env bash
# Start Security Graph on this machine with Docker: PostgreSQL, the API and the worker.
#
#   scripts/quickstart.sh            start (or update) the stack and create the first admin
#   scripts/quickstart.sh --demo     also load the Meridian Bank demonstration estate
#
# Safe to run again: secrets in .env are kept, and the admin is only created once.
set -euo pipefail

cd "$(dirname "$0")/.."

DEMO=0
for arg in "$@"; do
  case "$arg" in
    --demo) DEMO=1 ;;
    -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "Docker is required. Without Docker, use: make demo" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "The Docker Compose plugin is required." >&2; exit 1; }

random_hex() {  # random_hex <bytes>
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
  else head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

if [ ! -f .env ]; then
  umask 077
  sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(random_hex 24)|" \
      -e "s|^SECGRAPH_JWT_SECRET=.*|SECGRAPH_JWT_SECRET=$(random_hex 48)|" \
      .env.example > .env
  echo "Wrote .env with generated secrets (readable only by you)."
fi

docker compose up -d --build --wait

PORT="$(grep -E '^SECGRAPH_PORT=' .env | tail -1 | cut -d= -f2 || true)"
PORT="${PORT:-8080}"

users="$(docker compose exec -T api secgraph users list)"
if [ "$(printf '%s' "$users" | tr -d '[:space:]')" = "[]" ]; then
  # 3 character classes, 27 characters: satisfies the password policy.
  password="Sg-$(random_hex 12)"
  printf '%s\n' "$password" | docker compose exec -T api secgraph users create admin --roles admin --password-stdin >/dev/null
  created=1
else
  created=0
fi

if [ "$DEMO" = 1 ]; then
  docker compose exec -T api secgraph seed-demo
fi

echo
echo "Security Graph is running: http://127.0.0.1:${PORT}"
if [ "$created" = 1 ]; then
  echo "  username: admin"
  echo "  password: ${password}"
  echo "This password is not stored anywhere. Change it with:"
  echo "  docker compose exec api secgraph users set-password admin --password-stdin"
else
  echo "Users already exist; sign in with your account."
fi
echo "Check the installation:  docker compose exec api secgraph doctor"
echo "Stop:                    docker compose down      (add -v to delete the data)"

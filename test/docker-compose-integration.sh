#!/usr/bin/env bash
set -euo pipefail

PROJECT="vps-pilot-integration-$$"
TMP_DIR="$(mktemp -d)"
cleanup() {
  docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "$TMP_DIR/compose.yaml" <<'YAML'
services:
  database:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: disposable-integration
      POSTGRES_DB: pilot
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d pilot"]
      interval: 2s
      timeout: 2s
      retries: 10
  cache:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 2s
      retries: 10
YAML

docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" up -d --wait

STATUS="$(docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" ps --format json)"
[[ "$STATUS" == *'"Health":"healthy"'* ]]

docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" stop cache
if docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" ps --status running --format json | grep -q '"Service":"cache"'; then
  echo "failure-injection gate unexpectedly passed" >&2
  exit 1
fi

docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" start cache
docker compose -p "$PROJECT" -f "$TMP_DIR/compose.yaml" wait >/dev/null 2>&1 || true
echo "disposable Docker Compose integration passed"

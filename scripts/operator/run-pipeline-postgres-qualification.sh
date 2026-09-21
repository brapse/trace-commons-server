#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG_PORT="${TRACE_COMMONS_PIPELINE_QUALIFICATION_PG_PORT:-55442}"
CONTAINER="trace-commons-pipeline-qualification-tests-$$"

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for attempt in 1 2 3; do
  if docker run --rm --detach \
    --name "${CONTAINER}" \
    -e POSTGRES_PASSWORD=qualification-test \
    -p "127.0.0.1:${PG_PORT}:5432" \
    postgres:17-alpine >/dev/null; then
    break
  fi
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  if [[ "${attempt}" == "3" ]]; then
    echo "pipeline qualification PostgreSQL did not start" >&2
    exit 1
  fi
  sleep 1
done
for _ in $(seq 1 60); do
  if docker exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
docker exec "${CONTAINER}" pg_isready -U postgres >/dev/null

cd "${ROOT}"
ADMIN_URL="postgres://postgres:qualification-test@127.0.0.1:${PG_PORT}/postgres"
TRACE_COMMONS_PG_TEST_DATABASE_URL="${ADMIN_URL}" \
  RUSTFLAGS="-D warnings" \
  cargo test -p trace-commons-server --test versioned_pipeline_runtime_pg \
    pool_size_one_receipt_avoids_nested_checkout_and_saturation_is_bounded

docker exec "${CONTAINER}" psql -U postgres -v ON_ERROR_STOP=1 -c "
  CREATE ROLE pipeline_qualification_runtime
    LOGIN PASSWORD 'qualification-runtime'
    NOBYPASSRLS NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE;
  GRANT pipeline_claimer TO pipeline_qualification_runtime;
  GRANT CONNECT ON DATABASE postgres TO pipeline_qualification_runtime;
  GRANT USAGE ON SCHEMA public TO pipeline_qualification_runtime;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO pipeline_qualification_runtime;
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
    TO pipeline_qualification_runtime;
  GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public
    TO pipeline_qualification_runtime;
"

TRACE_COMMONS_PG_TEST_DATABASE_URL="postgres://pipeline_qualification_runtime:qualification-runtime@127.0.0.1:${PG_PORT}/postgres" \
  TRACE_COMMONS_PIPELINE_SKIP_TEST_MIGRATIONS=1 \
  TRACE_COMMONS_PIPELINE_REQUIRE_NOBYPASSRLS=1 \
  RUSTFLAGS="-D warnings" \
  cargo test -p trace-commons-server --test versioned_pipeline_runtime_pg

TRACE_COMMONS_PG_TEST_DATABASE_URL="postgres://pipeline_qualification_runtime:qualification-runtime@127.0.0.1:${PG_PORT}/postgres" \
  RUSTFLAGS="-D warnings" \
  cargo test -p trace-commons-server --bin trace-commons-ingest \
  real_ingest_pipeline_activation_routes_mixed_receipts_and_replays -- --test-threads=1

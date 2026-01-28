#!/usr/bin/env bash
set -euo pipefail

set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

echo "========================================="
echo "Running OTEL export integration test"
echo "========================================="

# This test is ignored by default and expects the OTEL collector stack to be running.
# Start it here to make CI/local runs self-contained.


OTLP_GRPC_PORT=4317
PROM_PORT=8889

if [[ -z "$OTLP_GRPC_PORT" || -z "$PROM_PORT" ]]; then
  echo "Failed to determine published ports from docker compose."
  docker compose --project-directory "$REPO_ROOT" -p "$COMPOSE_PROJECT_NAME" ps || true
  exit 1
fi

export OTEL_EXPORT_OTLP_ENDPOINT="http://127.0.0.1:${OTLP_GRPC_PORT}"
export OTEL_EXPORT_SCRAPE_URL="http://127.0.0.1:${PROM_PORT}/metrics"

echo "Checking OTEL collector Prometheus endpoint..."
for _ in {1..120}; do
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$OTEL_EXPORT_SCRAPE_URL" >/dev/null && break
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$OTEL_EXPORT_SCRAPE_URL" >/dev/null && break
  else
    # No HTTP client available: the test has its own retry loop.
    break
  fi
  sleep 0.5
done

# shellcheck disable=SC2086
cargo test -p cosmian_kms_server otel_export_metrics_uptime_and_active_keys $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} -- --ignored --nocapture

echo "OTEL export integration test completed successfully."

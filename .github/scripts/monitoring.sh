#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/../../"

cleanup() {
  echo "Stopping stack..."
  docker compose down -v --remove-orphans
}
trap cleanup EXIT INT TERM

echo "Starting observability stack with Docker Compose..."

docker compose up -d otel-collector tempo victoria-metrics alloy grafana

wait_for () {
  name=$1
  url=$2

  echo "Waiting for $name..."
  until curl -sf "$url" >/dev/null; do
    sleep 1
  done
  echo "$name ready"
}

wait_for "otel-collector" "http://localhost:8888/metrics"
wait_for "tempo" "http://localhost:3200/status"
wait_for "victoria-metrics" "http://localhost:8428/health"
wait_for "alloy" "http://localhost:12345/-/ready"
wait_for "grafana" "http://localhost:3000/api/health"

echo "All services are ready."

echo "Starting local KMS..."
cargo run -p cosmian_kms_server --features non-fips -- -c kms.toml
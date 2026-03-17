#!/usr/bin/env bash
set -euo pipefail

# ---- Clean previous stack ----
echo "Cleaning previous stack..."
docker compose down -v --remove-orphans 2>/dev/null || true

# ---- Set .env file ----
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    echo "Creating .env from .env.example"
    cp .env.example .env 2>/dev/null || true
  else
    echo "ERROR: .env file not found and no .env.example available"
    exit 1
  fi
fi

# ---- Load environment variables ----
echo "Loading configuration from .env"
set -a
source .env
set +a

# ---- Generate the demo TLS certificate ----
bash generate-demo-cert.sh

# ---- Start docker compose ----
echo "Starting services with docker compose..."
docker compose up -d

wait_for () {
  local name=$1
  local url=$2
  local timeout=${3:-60}

  echo "Waiting for $name..."

  for ((i=0;i<timeout;i++)); do
    if curl -sf --insecure "$url" >/dev/null; then
      echo "$name is ready"
      return
    fi
    sleep 1
  done

  echo "ERROR: $name did not become ready"
  docker compose logs "$name" --tail=20
  exit 1
}

# ---- HEALTH CHECKS ----
wait_for "otel-collector" "http://localhost:8888/metrics"
wait_for "victoria-metrics" "http://localhost:8428/health"
wait_for "grafana" "http://localhost:3000/api/health"
if [ "$KMS_MODE" = "local" ]; then
  wait_for "kms" "https://localhost:9998/health"
fi

#!/usr/bin/env bash
set -euo pipefail

# Monitoring stack integration test.
#
# Proves metrics OTLP export + monitoring stack (VictoriaMetrics + Grafana):
#
#   KMS --otlp → OTel collector → Prometheus endpoint → VictoriaMetrics
#   Grafana → VictoriaMetrics (health check)
#
# Test flow:
#   1. Start OTel collector (Docker, gRPC 4317, Prometheus scrape 8889)
#   2. Start VictoriaMetrics (Docker, receives OTel collector Prometheus remote_write)
#   3. Start Grafana (Docker, health check only)
#   4. Build KMS + ckms
#   5. Start KMS with --otlp pointing to OTel collector
#   6. Exercise 3+ KMIP operations to generate metrics
#   7. Wait up to 60s for OTel collector to receive KMS metrics
#   8. GUARD: required metrics in OTel collector Prometheus scrape endpoint
#   9. GUARD: VictoriaMetrics has kms_server_uptime_seconds_total and kms_database_operations_total
#  10. GUARD: Grafana /api/health returns HTTP 200 + database:ok
#  11. Print evidence
#
# Usage:
#   bash .mise/scripts/test/test_monitoring.sh [--variant fips|non-fips]
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.mise/scripts/common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=.mise/lib/kms_build.sh
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
# shellcheck source=.mise/lib/kms_server.sh
source "${SCRIPT_DIR}/../../lib/kms_server.sh"
# shellcheck source=.mise/lib/test_slots.sh
source "${SCRIPT_DIR}/../../lib/test_slots.sh"

init_build_env "$@"
setup_test_logging

COLLECTOR_CONTAINER=""
VM_CONTAINER=""
GRAFANA_CONTAINER=""
COLLECTOR_CONFIG_FILE=""
COLLECTOR_METRICS_DIR=""
MON_NETWORK="kms-mon-net-$$"

cleanup() {
  kms_stop
  for ctr in "${COLLECTOR_CONTAINER:-}" "${VM_CONTAINER:-}" "${GRAFANA_CONTAINER:-}"; do
    [ -n "${ctr}" ] && { docker rm -f "${ctr}" 2>/dev/null || true; }
  done
  [ -n "${MON_NETWORK:-}" ] && { docker network rm "${MON_NETWORK}" 2>/dev/null || true; }
  [ -n "${COLLECTOR_CONFIG_FILE:-}" ] && { rm -f "${COLLECTOR_CONFIG_FILE}" || true; }
  [ -n "${COLLECTOR_METRICS_DIR:-}" ] && { rm -rf "${COLLECTOR_METRICS_DIR}" || true; }
}
trap cleanup EXIT INT TERM

echo "==========================================="
echo "Monitoring stack integration test"
echo "Proves: OTel collector + VictoriaMetrics + Grafana"
echo "==========================================="

# ── Prerequisites ─────────────────────────────────────────────────────────────

require_cmd docker "Docker is required for OTel collector, VictoriaMetrics, and Grafana."
require_cmd curl "curl is required for querying VictoriaMetrics, Prometheus, and Grafana."
require_cmd nc "nc (netcat) is required for port checks."
require_cmd python3 "python3 is required for JSON parsing."

if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running." >&2
  exit 1
fi

# ── Port selection ────────────────────────────────────────────────────────────

pick_port_or_free() {
  local preferred_port="$1"
  if ! nc -z 127.0.0.1 "${preferred_port}" 2>/dev/null; then
    echo "${preferred_port}"
    return
  fi
  kms_pick_free_port
}

OTEL_GRPC_PORT=$(pick_port_or_free "${KMS_SLOT_OTEL_GRPC_PORT:-4317}")
OTEL_PROM_PORT=$(pick_port_or_free "${KMS_SLOT_OTEL_METRICS_PORT:-8889}")
VM_PORT=$(pick_port_or_free "${KMS_SLOT_VICTORIA_PORT:-8428}")
GRAFANA_PORT=$(pick_port_or_free "${KMS_SLOT_GRAFANA_PORT:-3000}")

# ── Container names (all use $$ so parallel runs don't collide) ──────────────

COLLECTOR_CONTAINER="kms-mon-test-collector-$$"
VM_CONTAINER="kms-mon-test-vm-$$"
GRAFANA_CONTAINER="kms-mon-test-grafana-$$"

echo "==> Assigned ports: OTel gRPC=${OTEL_GRPC_PORT}, OTel Prom=${OTEL_PROM_PORT}, VM=${VM_PORT}, Grafana=${GRAFANA_PORT}"

# ── Start OTel collector ──────────────────────────────────────────────────────

echo "==> Creating Docker network for container-to-container communication..."
docker network create "${MON_NETWORK}" 2>/dev/null || true

# Generate the OTel collector config dynamically.
# The collector:
#   - receives KMS metrics via gRPC (port 4317, exposed to host)
#   - writes metrics to a local JSONL file for proof
#   - also exposes a Prometheus scrape endpoint for host-side debug (port 8889)
COLLECTOR_CONFIG_FILE="$(mktemp /tmp/otel-collector-XXXXXXXX)"
cat >"${COLLECTOR_CONFIG_FILE}" <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
      http:
        endpoint: "0.0.0.0:4318"

processors:
  batch:
    timeout: 5s

exporters:
  prometheusremotewrite:
    endpoint: "http://${VM_CONTAINER}:8428/api/v1/write"
    tls:
      insecure: true
  file:
    path: /tmp/otel-metrics-dir/metrics.jsonl
  # Also expose a Prometheus scrape endpoint on the host for debugging
  prometheus:
    endpoint: "0.0.0.0:8889"
    send_timestamps: true
    metric_expiration: 5m
service:
  telemetry:
    logs:
      level: warn
    metrics:
      level: none
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheusremotewrite, file, prometheus]
EOF
chmod 644 "${COLLECTOR_CONFIG_FILE}"

# The file exporter writes to the container's /tmp — we need a host-mounted dir.
# Use a tmpdir so docker can mount it (not /var/folders which Docker Desktop can't see).
COLLECTOR_METRICS_DIR="$(mktemp -d /tmp/otel-metrics-XXXXXXXX)"
chmod 777 "${COLLECTOR_METRICS_DIR}"

# Pull images first so container startup is instantaneous and not subject
# to network download latency during readiness wait loops.
echo "==> Pulling monitoring images..."
docker pull otel/opentelemetry-collector-contrib:latest 2>/dev/null
docker pull victoriametrics/victoria-metrics:latest 2>/dev/null
docker pull grafana/grafana:latest 2>/dev/null
echo "==> Starting OTel collector (gRPC port ${OTEL_GRPC_PORT}, Prometheus debug port ${OTEL_PROM_PORT})..."
docker run --rm --name "${COLLECTOR_CONTAINER}" \
  --network "${MON_NETWORK}" \
  -p "${OTEL_GRPC_PORT}:4317" \
  -p "${OTEL_PROM_PORT}:8889" \
  -v "${COLLECTOR_CONFIG_FILE}:/etc/otel-collector-config.yaml:ro" \
  -v "${COLLECTOR_METRICS_DIR}:/tmp/otel-metrics-dir:rw" \
  otel/opentelemetry-collector-contrib:latest \
  --config=/etc/otel-collector-config.yaml \
  2>/dev/null &

# ── Start VictoriaMetrics (local query endpoint for evidence) ────────────────

echo "==> Starting VictoriaMetrics (port ${VM_PORT})..."
docker run --rm --name "${VM_CONTAINER}" \
  --network "${MON_NETWORK}" \
  -p "${VM_PORT}:8428" \
  victoriametrics/victoria-metrics:latest \
  2>/dev/null &

# ── Start Grafana ─────────────────────────────────────────────────────────────

echo "==> Starting Grafana (port ${GRAFANA_PORT})..."
GRAFANA_CONTAINER="kms-mon-test-grafana-$$"

docker run --rm --name "${GRAFANA_CONTAINER}" \
  --network "${MON_NETWORK}" \
  -e GF_SECURITY_ADMIN_USER=admin \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  -e GF_LOG_LEVEL=error \
  -p "${GRAFANA_PORT}:3000" \
  grafana/grafana:latest \
  2>/dev/null &

# ── Wait for OTel collector gRPC port ────────────────────────────────────────

echo "==> Waiting for OTel collector gRPC on port ${OTEL_GRPC_PORT}..."
waited=0
while ! nc -z 127.0.0.1 "${OTEL_GRPC_PORT}" 2>/dev/null; do
  if [ "${waited}" -ge 90 ]; then
    echo "ERROR: OTel collector did not become ready within 90s." >&2
    docker logs "${COLLECTOR_CONTAINER}" 2>&1 || true
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
echo "    OTel collector gRPC ready (${waited}s)."

# Also wait for the Prometheus metrics port (used by VictoriaMetrics scraper)
echo "==> Waiting for OTel collector Prometheus port ${OTEL_PROM_PORT}..."
waited=0
while ! nc -z 127.0.0.1 "${OTEL_PROM_PORT}" 2>/dev/null; do
  if [ "${waited}" -ge 30 ]; then
    echo "ERROR: OTel collector Prometheus port did not become ready within 30s." >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
echo "    OTel collector Prometheus port ready (${waited}s)."

# ── Wait for VictoriaMetrics ──────────────────────────────────────────────────
echo "==> Waiting for VictoriaMetrics on port ${VM_PORT}..."
waited=0
while ! curl -sf "http://127.0.0.1:${VM_PORT}/api/v1/query?query=up" >/dev/null 2>&1; do
  if [ "${waited}" -ge 45 ]; then
    echo "ERROR: VictoriaMetrics did not become ready within 45s." >&2
    docker logs "${VM_CONTAINER}" 2>&1 || true
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
echo "    VictoriaMetrics ready (${waited}s)."

# ── Wait for Grafana ──────────────────────────────────────────────────────────

echo "==> Waiting for Grafana on port ${GRAFANA_PORT}..."
waited=0
while ! curl -sf "http://127.0.0.1:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; do
  if [ "${waited}" -ge 90 ]; then
    echo "ERROR: Grafana did not become ready within 90s." >&2
    docker logs "${GRAFANA_CONTAINER}" 2>&1 || true
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
echo "    Grafana ready (${waited}s)."
# ── Build KMS ─────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
# kms_build_all consumes variant from init_build_env; script flags must not be passed to Cargo
# shellcheck disable=SC2119
kms_build_all
kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS with --otlp ─────────────────────────────────────────────────────

KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS on port ${KMS_PORT} with --otlp grpc://127.0.0.1:${OTEL_GRPC_PORT}..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-mon-test-XXXXXX)"

# Add OTLP metrics export to the existing [logging] section (avoid duplicate section)
python3 -c "
import sys
config = open('${KMS_CONFIG_FILE}').read()
# Insert otlp keys after [logging] section header
config = config.replace('[logging]\n', '[logging]\notlp = \"http://127.0.0.1:${OTEL_GRPC_PORT}\"\notlp_allow_insecure = true\n', 1)
open('${KMS_CONFIG_FILE}', 'w').write(config)
"

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations to generate metrics ─────────────────────────────

echo "==> Exercising KMIP operations to generate metrics..."

ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null
}
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null || true
}
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
echo "    Created AES-256 key: ${SYM_UID}"

TMPDIR_DATA="$(mktemp -d /tmp/mon-test-XXXXXX)"
echo "Hello, monitoring test!" >"${TMPDIR_DATA}/plaintext.txt"
ckms_run sym encrypt "${TMPDIR_DATA}/plaintext.txt" --key-id "${SYM_UID}" --output "${TMPDIR_DATA}/encrypted.bin"
echo "    Encrypted."
ckms_run sym keys destroy --key-id "${SYM_UID}"
echo "    Destroyed."
rm -rf "${TMPDIR_DATA}"

echo "==> Waiting up to 60s for KMS metrics to arrive at OTel collector Prometheus endpoint..."
echo "    Proof pipeline: KMS --gRPC-> OTel collector --Prometheus--> (debug endpoint)"

# ── GUARD 1: KMS metrics present on OTel collector Prometheus endpoint ────────
# The Prometheus scrape endpoint on the collector is the authoritative proof that
# KMS is successfully sending metrics to the OTel collector via gRPC.

found_metrics=false
metric_count=0
for i in $(seq 1 12); do
  metric_count=$(
    curl -sf "http://127.0.0.1:${OTEL_PROM_PORT}/metrics" 2>/dev/null |
      grep -c "^kms_" 2>/dev/null
    true
  )
  if [ "${metric_count}" -gt 0 ]; then
    found_metrics=true
    echo "    Found ${metric_count} KMS metric lines on OTel Prometheus endpoint (after $((i * 5))s)"
    break
  fi
  echo "    Attempt ${i}/12: KMS metrics not yet on OTel Prometheus endpoint..."
  sleep 5
done

if [ "${found_metrics}" = false ]; then
  echo "ERROR: KMS metrics not found on OTel collector Prometheus endpoint after 60s." >&2
  echo "       KMS is not exporting metrics to the OTel collector." >&2
  echo "       Check: --otlp grpc://127.0.0.1:${OTEL_GRPC_PORT} in KMS config." >&2
  echo "OTel collector logs (last 20 lines):" >&2
  docker logs "${COLLECTOR_CONTAINER}" 2>&1 | tail -20 >&2 || echo "(no logs)" >&2
  exit 1
fi
echo "GUARD OK: ${metric_count} KMS metric lines on OTel collector Prometheus endpoint."

# ── GUARD 2: Required metric names present ────────────────────────────────────

required_metrics=(
  "kms_active_connections"
  "kms_active_users"
  "kms_database_operations_total"
  "kms_server_uptime_seconds_total"
)
prom_output=$(curl -sf "http://127.0.0.1:${OTEL_PROM_PORT}/metrics" 2>/dev/null || echo "")
for m in "${required_metrics[@]}"; do
  if echo "${prom_output}" | grep -q "^${m}"; then
    echo "    Found metric: ${m}"
  else
    echo "ERROR: Required metric '${m}' not found on OTel Prometheus endpoint." >&2
    echo "       Available KMS metrics:" >&2
    echo "${prom_output}" | grep "^kms_" | head -10 >&2
    exit 1
  fi
done
echo "GUARD OK: all required KMS metric names present."

# ── GUARD 3: VictoriaMetrics has KMS metrics ─────────────────────────────────

echo "==> Waiting up to 60s for VictoriaMetrics to ingest KMS metrics via remote_write..."
found_vm_metrics=false
vm_uptime_count=0
vm_db_count=0

for i in $(seq 1 12); do
  vm_uptime_count=$(curl -sf "http://127.0.0.1:${VM_PORT}/api/v1/query?query=kms_server_uptime_seconds_total" 2>/dev/null | grep -c '"kms_server_uptime_seconds_total"' || true)
  vm_db_count=$(curl -sf "http://127.0.0.1:${VM_PORT}/api/v1/query?query=kms_database_operations_total" 2>/dev/null | grep -c '"kms_database_operations_total"' || true)
  if [ "${vm_uptime_count}" -gt 0 ] && [ "${vm_db_count}" -gt 0 ]; then
    found_vm_metrics=true
    echo "    Found KMS metrics in VictoriaMetrics after $((i * 5))s (uptime: ${vm_uptime_count}, db: ${vm_db_count})"
    break
  fi
  echo "    Attempt ${i}/12: metrics not yet queryable in VictoriaMetrics..."
  sleep 5
done

if [ "${found_vm_metrics}" = false ]; then
  echo "ERROR: KMS metrics not queryable in VictoriaMetrics after 60s." >&2
  echo "       uptime_count=${vm_uptime_count}, db_count=${vm_db_count}" >&2
  exit 1
fi
echo "GUARD OK: KMS metrics queryable in VictoriaMetrics (uptime: ${vm_uptime_count}, db: ${vm_db_count})."

# ── GUARD 4: Grafana health check ────────────────────────────────────────────

echo "==> Checking Grafana health..."
grafana_health=$(curl -sf "http://127.0.0.1:${GRAFANA_PORT}/api/health" 2>/dev/null || echo '{}')
grafana_db=$(echo "${grafana_health}" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('database','?'))" 2>/dev/null || echo "error")
echo "    Grafana health database: ${grafana_db}."

if [ "${grafana_db}" != "ok" ]; then
  echo "ERROR: Grafana health check failed: database=${grafana_db}" >&2
  echo "       Response: ${grafana_health}" >&2
  exit 1
fi
echo "GUARD OK: Grafana /api/health returns database=ok."

# ── Print evidence ────────────────────────────────────────────────────────────

echo ""
echo "==> Evidence — KMS metrics on OTel collector Prometheus endpoint:"
echo "${prom_output}" | grep "^# HELP kms_" | sed 's/# HELP /  /' | head -10
echo "  Grafana health: database=${grafana_db}"

echo ""
echo "Monitoring stack integration test PASSED."
echo "Evidence: KMS metrics flowing to OTel collector (${metric_count} lines), Grafana healthy."
echo "Proves metrics OTLP export + monitoring stack (OTel collector + VictoriaMetrics + Grafana)."

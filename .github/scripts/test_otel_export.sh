#!/usr/bin/env bash
set -euo pipefail

set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

# This script replaces the (ignored) Rust integration test by:
# - starting the KMS server with `cargo run -p ...`
# - creating and activating keys via the CLI against the running server
# - scraping the collector Prometheus endpoint and asserting expected metrics

KMS_HTTP_HOST=127.0.0.1
KMS_HTTP_PORT=18080

OTLP_GRPC_PORT=4317
PROM_PORT=8889

export OTEL_EXPORT_OTLP_ENDPOINT="http://127.0.0.1:${OTLP_GRPC_PORT}"
OTEL_EXPORT_SCRAPE_URL="http://127.0.0.1:${PROM_PORT}/metrics"

KMS_PID=""

collector_metrics_probe() {
  # Emit a single-line probe result that is easy to log and parse under bash 3.2+.
  # Example: "curl_exit=0 http=200 size=8714"
  local out curl_status http_code size
  out=$(curl -sS --max-time 2 -o /dev/null -w "%{http_code} %{size_download}" "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null || true)
  curl_status=$?
  http_code="${out%% *}"
  size="${out##* }"
  if [ -z "${http_code}" ] || [ "${http_code}" = "${out}" ]; then
    http_code="000"
  fi
  if [ -z "${size}" ] || [ "${size}" = "${out}" ]; then
    size="0"
  fi
  echo "curl_exit=${curl_status} http=${http_code} size=${size}"
}

collector_metrics_body() {
  curl -fsS --max-time 2 "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null || true
}

collector_metrics_size() {
  collector_metrics_body | wc -c | tr -d ' '
}

collector_metrics_has_any_series() {
  local body="$1"
  # Prometheus exposition format usually includes at least one HELP/TYPE line or
  # a metric sample. Consider it "non-empty" only if it contains something
  # that looks like metrics content.
  echo "${body}" | grep -Eq '^(# (HELP|TYPE) |[a-zA-Z_:][a-zA-Z0-9_:]*\{?|[a-zA-Z_:][a-zA-Z0-9_:]*[[:space:]])' || return 1
}

collector_metrics_has_expected_series() {
  local body="$1"
  # Prefer checking for server metrics we know should exist once KMS exports.
  echo "${body}" | grep -Eq '^(kms_server_uptime_seconds_total|kms_server_start_time_seconds)(\{|[[:space:]])' || return 1
}

metric_value_from_body() {
  local metric_name="$1"
  local body="$2"
  # Prometheus exposition samples look like:
  #   name{labels} <value> [timestamp]
  # Print the first observed numeric value (no trailing newline if missing).
  echo "${body}" | awk -v name="${metric_name}" '
    $1 ~ ("^"name"(\\{|$)") { print $2; exit }
  '
}

dump_debug_state() {
  echo "=========================================" >&2
  echo "OTEL export debug dump" >&2
  echo "=========================================" >&2

  echo "-- Environment (OTEL/KMS)" >&2
  env | sort | grep -E '^(OTEL_|KMS_)' >&2 || true

  if [ -n "${KMS_CONF_PATH:-}" ] && [ -f "${KMS_CONF_PATH}" ]; then
    echo "-- KMS config: ${KMS_CONF_PATH}" >&2
    cat "${KMS_CONF_PATH}" >&2 || true
  fi

  echo "-- Collector config (unredacted)" >&2
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" exec -T otel-collector \
    /otelcol-contrib print-config --config=/etc/otel-collector-config.yaml --mode=unredacted \
    >&2 || true

  echo "-- Collector logs (tail)" >&2
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true

  echo "-- Collector container status" >&2
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" ps otel-collector >&2 || true
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" port otel-collector 4317 >&2 || true
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" port otel-collector 8889 >&2 || true

  echo "-- Collector /metrics probe" >&2
  collector_metrics_probe >&2 || true

  echo "-- Collector /metrics headers" >&2
  curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true

  echo "-- Collector /metrics size" >&2
  curl -fsS --max-time 2 "${OTEL_EXPORT_SCRAPE_URL}" | wc -c >&2 || true
}

# The collector exposes Prometheus metrics (both its own telemetry and
# OTLP-received metrics) via the HTTP exporter at 8889.
compose_up_collector() {
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" up -d otel-collector

  # Wait for the endpoint to be ready.
  # In CI (and locally), we can observe HTTP 200 with Content-Length: 0 until
  # the KMS starts exporting metrics. Treat readiness as: endpoint responds.
  for _ in {1..120}; do
    if curl -fsS -o /dev/null "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done

  echo "OTEL collector did not become ready (HTTP endpoint not responding) at ${OTEL_EXPORT_SCRAPE_URL}" >&2
  echo "Collector /metrics headers:" >&2
  curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true
  echo "Collector /metrics size:" >&2
  collector_metrics_size >&2 || true
  docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true
  return 1
}

cleanup() {
  # Preserve the script exit status; otherwise the last command in this
  # EXIT trap (e.g., wait) can overwrite it.
  local status=$?
  set +e
  # Only dump diagnostics if something looks wrong.
  # Note: `curl -f` + pipe can print "0" even on connection errors, so use a probe.
  if [ -n "${OTEL_EXPORT_SCRAPE_URL:-}" ]; then
    probe=$(collector_metrics_probe || true)
    local probe_curl probe_http_field probe_size_field
    IFS=' ' read -r probe_curl probe_http_field probe_size_field <<<"${probe}"
    probe_curl_exit="${probe_curl#curl_exit=}"
    probe_http="${probe_http_field#http=}"
    probe_size="${probe_size_field#size=}"
  else
    probe_curl_exit=""
    probe_http=""
    probe_size=""
  fi
  if [ -n "${probe_http}" ] && { [ "${probe_curl_exit}" != "0" ] || [ "${probe_http}" != "200" ] || [ "${probe_size}" -eq 0 ]; }; then
    dump_debug_state || true
  fi
  if [ -n "${KMS_PID}" ]; then
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  fi

  return "$status"
}

wait_for_kms_listen() {
  local url="http://${KMS_HTTP_HOST}:${KMS_HTTP_PORT}/kmip/2_1"
  echo "Waiting for KMS to accept HTTP connections..."

  for _ in {1..240}; do
    # If the process died early, surface logs.
    if ! kill -0 "${KMS_PID}" 2>/dev/null; then
      echo "KMS process exited early. KMS log tail:" >&2
      tail -n 200 "${LOG_PATH}" >&2 || true
      exit 1
    fi

    # Probe KMIP endpoint with empty JSON body. Any HTTP response code means the server is up.
    if curl -sS -o /dev/null -w "%{http_code}" -X POST "${url}" -H "Content-Type: application/json" -d '{}' | grep -Eq '^[0-9]{3}$'; then
      return 0
    fi

    sleep 0.5
  done

  echo "Timed out waiting for KMS to accept HTTP connections." >&2
  echo "KMS log tail:" >&2
  tail -n 200 "${LOG_PATH}" >&2 || true
  return 1
}

kmip_post() {
  local payload="$1"
  # Don't use -f: we want the response body even on HTTP 4xx.
  curl -sS -X POST "http://${KMS_HTTP_HOST}:${KMS_HTTP_PORT}/kmip/2_1" \
    -H "Content-Type: application/json" \
    -d "${payload}"
}

create_aes_key() {
  # Create an AES-256 key by sending a KMIP JSON-TTLV Operation.
  # This must match the documented request shape in `documentation/docs/kmip/_create.md`.
  kmip_post '{
    "tag": "Create",
    "type": "Structure",
    "value": [
      {
        "tag": "ObjectType",
        "type": "Enumeration",
        "value": "SymmetricKey"
      },
      {
        "tag": "Attributes",
        "type": "Structure",
        "value": [
          {
            "tag": "CryptographicAlgorithm",
            "type": "Enumeration",
            "value": "AES"
          },
          {
            "tag": "CryptographicLength",
            "type": "Integer",
            "value": 256
          },
          {
            "tag": "KeyFormatType",
            "type": "Enumeration",
            "value": "TransparentSymmetricKey"
          },
          {
            "tag": "ObjectType",
            "type": "Enumeration",
            "value": "SymmetricKey"
          }
        ]
      }
    ]
  }'
}

activate_key() {
  local uid="$1"
  # Minimal KMIP JSON-TTLV Activate request.
  kmip_post "{\"tag\":\"Activate\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${uid}\"}]}"
}

extract_uid() {
  # Extract UniqueIdentifier from the KMIP JSON response.
  # Use perl for portability (macOS awk lacks some gawk features).
  perl -0777 -ne 'if (m/"tag"\s*:\s*"UniqueIdentifier".*?"value"\s*:\s*"([^"]+)"/s) { print "$1\n"; }'
}

wait_for_metric_gt() {
  local metric_name="$1"
  local min="$2"
  local timeout_secs="$3"
  local start
  start=$(date +%s)

  while true; do
    body=$(collector_metrics_body)
    if echo "${body}" | awk -v name="${metric_name}" -v min="${min}" '
      $1 ~ ("^"name"(\\{|$)") {
        if (($2+0) > (min+0)) { ok=1 }
      }
      END { exit(ok?0:1) }
    '; then
      return 0
    fi

    now=$(date +%s)
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "Timed out waiting for ${metric_name} > ${min}. Last scrape:" >&2
      echo "${body}" >&2
      if [ -z "${body}" ]; then
        echo "Collector /metrics headers:" >&2
        curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true
        echo "Collector logs (tail):" >&2
        docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true
      fi
      return 1
    fi
    sleep 0.5
  done
}

wait_for_metric_eq() {
  local metric_name="$1"
  local expected="$2"
  local timeout_secs="$3"
  local start
  start=$(date +%s)

  while true; do
    body=$(collector_metrics_body)
    if echo "${body}" | awk -v name="${metric_name}" -v expected="${expected}" '
      $1 ~ ("^"name"(\\{|$)") {
        if (NF >= 2 && ($2+0) == (expected+0)) { ok=1 }
      }
      END { exit(ok?0:1) }
    '; then
      return 0
    fi

    now=$(date +%s)
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "Timed out waiting for ${metric_name} == ${expected}. Last scrape:" >&2
      echo "${body}" >&2
      if [ -z "${body}" ]; then
        echo "Collector /metrics headers:" >&2
        curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true
        echo "Collector logs (tail):" >&2
        docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true
      fi
      return 1
    fi
    sleep 0.5
  done
}

wait_for_metric_any_uptime_gt() {
  local timeout_secs="$1"
  local start
  start=$(date +%s)

  while true; do
    body=$(collector_metrics_body)
    if echo "${body}" | awk '
      $1 ~ /^kms_server_uptime_seconds_total(\{|$)/ {
        if (NF >= 2 && ($2+0) > 0) { ok=1 }
      }
      END { exit(ok?0:1) }
    '; then
      return 0
    fi

    now=$(date +%s)
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "Timed out waiting for kms_server_uptime_seconds_total > 0. Last scrape:" >&2
      echo "${body}" >&2
      if [ -z "${body}" ]; then
        echo "Collector /metrics headers:" >&2
        curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true
        echo "Collector logs (tail):" >&2
        docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true
      fi
      return 1
    fi
    sleep 0.5
  done
}

wait_for_server_uptime_using_start_time() {
  local timeout_secs="$1"
  local start
  start=$(date +%s)

  while true; do
    body=$(collector_metrics_body)
    if echo "${body}" | awk -v now="$(date +%s)" '
      $1 ~ /^kms_server_start_time_seconds(\{|$)/ {
        start=$2+0
        if (start > 0 && start <= now) {
          if ((now - start) > 0) ok=1
        }
      }
      END { exit(ok?0:1) }
    '; then
      return 0
    fi

    now=$(date +%s)
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "Timed out waiting for kms_server_start_time_seconds to imply uptime > 0. Last scrape:" >&2
      echo "${body}" >&2
      if [ -z "${body}" ]; then
        echo "Collector /metrics headers:" >&2
        curl -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2 || true
        echo "Collector logs (tail):" >&2
        docker compose -f "${SCRIPT_DIR}/../../docker-compose.yml" logs --no-color --tail 200 otel-collector >&2 || true
      fi
      return 1
    fi
    sleep 0.5
  done
}

main() {
  init_build_env "$@"
  setup_test_logging

  require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."
  require_cmd docker "Docker is required to run the OTEL collector stack. Start Docker and retry."
  require_cmd curl "curl is required to scrape the collector metrics endpoint. Install it and retry."

  echo "========================================="
  echo "Running OTEL export integration test"
  echo "========================================="

  trap cleanup EXIT

  echo "Starting KMS server (background)..."

  # Ensure the collector stack is up before we start exporting.
  compose_up_collector

  # The server expects `sqlite_path` to be a directory where it creates `kms.db`.
  SQLITE_PATH="$(mktemp -d -t kms-otel-XXXXXX)"

  # Write a minimal server config so we can control HTTP bind + sqlite path.
  KMS_CONF_PATH="$(mktemp -t kms-otel-conf-XXXXXX.toml)"
  cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "${KMS_HTTP_HOST}"
port = ${KMS_HTTP_PORT}

[logging]
enable_metering = true
otlp = "${OTEL_EXPORT_OTLP_ENDPOINT}"

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true
EOF

  LOG_PATH="${LOG_PATH:-/tmp/kms-otel-export.log}"
  rm -f "${LOG_PATH}" || true

  # Start the server with OTEL export enabled.
  # shellcheck disable=SC2086
  stdbuf -oL -eL cargo run -p cosmian_kms_server $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --bin cosmian_kms -- \
    --config "${KMS_CONF_PATH}" \
    >"${LOG_PATH}" 2>&1 &

  KMS_PID=$!

  wait_for_kms_listen

  echo "Creating + activating symmetric keys via KMIP JSON endpoint..."

  for i in {1..10}; do
    resp=$(create_aes_key)
    if echo "${resp}" | grep -q '"tag"[[:space:]]*:[[:space:]]*"ResponseMessage"'; then
      echo "Create failed with KMIP error response (iteration ${i}):" >&2
      echo "${resp}" >&2
      echo "KMS log tail:" >&2
      tail -n 200 /tmp/kms-otel-export.log >&2 || true
      exit 1
    fi

    # New-style success responses are `CreateResponse` with a top-level `value` array.
    if echo "${resp}" | grep -q '^Invalid Request:'; then
      echo "Create failed (iteration ${i}):" >&2
      echo "${resp}" >&2
      echo "KMS log tail:" >&2
      tail -n 200 /tmp/kms-otel-export.log >&2 || true
      exit 1
    fi
    uid=$(printf '%s' "${resp}" | extract_uid)
    if [ -z "${uid}" ]; then
      echo "Failed to parse unique identifier from Create response (iteration ${i})." >&2
      echo "Response was: ${resp}" >&2
      echo "KMS log tail:" >&2
      tail -n 200 /tmp/kms-otel-export.log >&2 || true
      exit 1
    fi
    activate_key "${uid}" >/dev/null
  done

  echo "Waiting for exported metrics (uptime + active keys)..."

  # Prefer an explicit uptime metric if present, otherwise fall back
  # to the exported start time gauge.
  if ! wait_for_metric_any_uptime_gt 30; then
    wait_for_server_uptime_using_start_time 120
  fi

  # Active keys should reflect our 10 activated keys.
  # This is a hard/blocking requirement (script fails on mismatch/timeout).
  wait_for_metric_eq "kms_keys_active_count" 10 180

  # Echo what we observed to help diagnose CI flakiness.
  body=$(collector_metrics_body)
  observed_active_keys=$(metric_value_from_body "kms_keys_active_count" "${body}")
  echo "Observed kms_keys_active_count=${observed_active_keys:-<missing>}"

  echo "OTEL export integration script completed successfully."
}

main "$@"

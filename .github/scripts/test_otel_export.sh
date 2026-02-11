#!/usr/bin/env bash
set -euo pipefail

# Enable xtrace only when explicitly requested. Unconditional xtrace makes CI logs
# extremely noisy (and can lead to spurious job termination).
case "${KMS_TEST_TRACE:-0}" in
  1|true|TRUE|yes|YES)
    set -x
    ;;
esac

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

# This script replaces the (ignored) Rust integration test by:
# - starting the KMS server with `cargo run -p ...`
# - creating and activating keys via the CLI against the running server
# - scraping the collector Prometheus endpoint and asserting expected metrics

KMS_HTTP_HOST=127.0.0.1
KMS_HTTP_PORT=18080

OTLP_GRPC_PORT=${OTLP_GRPC_PORT:-4317}
PROM_PORT=${PROM_PORT:-8889}

export OTEL_EXPORT_OTLP_ENDPOINT="${OTEL_EXPORT_OTLP_ENDPOINT:-http://127.0.0.1:${OTLP_GRPC_PORT}}"
OTEL_EXPORT_SCRAPE_URL="${OTEL_EXPORT_SCRAPE_URL:-http://127.0.0.1:${PROM_PORT}/metrics}"

KMS_PID=""

# In the FIPS Nix shell, we intentionally export OPENSSL_* and may set
# LD_LIBRARY_PATH/LD_PRELOAD to force the server to use the FIPS-validated
# OpenSSL runtime. That global override can break Nix-provided tools built
# against newer OpenSSL (e.g., curl/libcurl requiring OPENSSL_3.2.0+).
#
# For this test we only use curl for plain HTTP probes/scrapes; it does not
# need the server's OpenSSL runtime. Run curl in a clean environment so it
# uses its own Nix rpaths.
curl_clean_env() {
  env -u LD_LIBRARY_PATH -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
    curl "$@"
}

collector_metrics_probe() {
  # Emit a single-line probe result that is easy to log and parse under bash 3.2+.
  # Example: "curl_exit=0 http=200 size=8714"
  local out curl_status http_code size
  if out=$(curl_clean_env -sS --max-time 2 -o /dev/null -w "%{http_code} %{size_download}" "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null); then
    curl_status=0
  else
    curl_status=$?
    out=""
  fi
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
  if curl_clean_env -fsS --max-time 2 "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null; then
    return 0
  fi
  return 0
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
  env | sort | awk '/^(OTEL_|KMS_)/ { print }' >&2

  if [ -n "${KMS_CONF_PATH:-}" ] && [ -f "${KMS_CONF_PATH}" ]; then
    echo "-- KMS config: ${KMS_CONF_PATH}" >&2
    if ! cat "${KMS_CONF_PATH}" >&2; then
      echo "Failed to read KMS config: ${KMS_CONF_PATH}" >&2
    fi
  fi

  if [ -n "${LOG_PATH:-}" ] && [ -f "${LOG_PATH}" ]; then
    echo "-- KMS logs (tail)" >&2
    if ! tail -n 200 "${LOG_PATH}" >&2; then
      echo "Failed to read KMS log: ${LOG_PATH}" >&2
    fi
  fi

  echo "-- Collector /metrics probe" >&2
  collector_metrics_probe >&2

  echo "-- Collector /metrics headers" >&2
  if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
    echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
  fi

  echo "-- Collector /metrics size" >&2
  if ! curl_clean_env -fsS --max-time 2 "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null | wc -c >&2; then
    echo "Failed to fetch collector metrics body from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
  fi
}

wait_for_collector_http_endpoint() {
  # We only require the endpoint to respond; it may legitimately be empty until
  # KMS starts exporting.
  # CI can be slow to pull/start the collector image; allow a bit more time.
  for _ in {1..240}; do
    if curl_clean_env -fsS -o /dev/null "${OTEL_EXPORT_SCRAPE_URL}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done

  echo "OTEL collector did not become ready (HTTP endpoint not responding) at ${OTEL_EXPORT_SCRAPE_URL}" >&2
  echo "Collector /metrics headers:" >&2
  if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
    echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
  fi
  echo "Collector /metrics size:" >&2
  collector_metrics_size >&2
  return 1
}

cleanup() {
  # Preserve the script exit status; otherwise the last command in this
  # EXIT trap (e.g., wait) can overwrite it.
  local status=$?

  # Only dump diagnostics if something looks wrong.
  # Note: `curl -f` + pipe can print "0" even on connection errors, so use a probe.
  if [ -n "${OTEL_EXPORT_SCRAPE_URL:-}" ]; then
    probe=$(collector_metrics_probe)
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
    if ! dump_debug_state; then
      echo "Debug dump failed" >&2
    fi
  fi
  if [ -n "${KMS_PID}" ]; then
    if kill -0 "${KMS_PID}" 2>/dev/null; then
      if ! kill "${KMS_PID}" 2>/dev/null; then
        echo "Failed to stop KMS PID ${KMS_PID}" >&2
      fi
      if ! wait "${KMS_PID}" 2>/dev/null; then
        echo "KMS PID ${KMS_PID} did not exit cleanly" >&2
      fi
    fi
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
      if ! tail -n 200 "${LOG_PATH}" >&2; then
        echo "Failed to read KMS log: ${LOG_PATH}" >&2
      fi
      exit 1
    fi

    # Probe KMIP endpoint with empty JSON body. Any HTTP response code means the server is up.
    if curl_clean_env -sS -o /dev/null -w "%{http_code}" -X POST "${url}" -H "Content-Type: application/json" -d '{}' 2>/dev/null | grep -Eq '^[0-9]{3}$'; then
      return 0
    fi

    sleep 0.5
  done

  echo "Timed out waiting for KMS to accept HTTP connections." >&2
  echo "KMS log tail:" >&2
  if ! tail -n 200 "${LOG_PATH}" >&2; then
    echo "Failed to read KMS log: ${LOG_PATH}" >&2
  fi
  return 1
}

kmip_post() {
  local payload="$1"
  # Don't use -f: we want the response body even on HTTP 4xx.
  curl_clean_env -sS -X POST "http://${KMS_HTTP_HOST}:${KMS_HTTP_PORT}/kmip/2_1" \
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
        if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
          echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
        fi
        echo "Collector /metrics probe:" >&2
        collector_metrics_probe >&2
        echo "Collector /metrics size:" >&2
        collector_metrics_size >&2
        if [ -n "${LOG_PATH:-}" ] && [ -f "${LOG_PATH}" ]; then
          echo "KMS log tail:" >&2
          if ! tail -n 200 "${LOG_PATH}" >&2; then
            echo "Failed to read KMS log: ${LOG_PATH}" >&2
          fi
        fi
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
        if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
          echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
        fi
        echo "Collector /metrics probe:" >&2
        collector_metrics_probe >&2
        echo "Collector /metrics size:" >&2
        collector_metrics_size >&2
        if [ -n "${LOG_PATH:-}" ] && [ -f "${LOG_PATH}" ]; then
          echo "KMS log tail:" >&2
          if ! tail -n 200 "${LOG_PATH}" >&2; then
            echo "Failed to read KMS log: ${LOG_PATH}" >&2
          fi
        fi
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
        if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
          echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
        fi
        echo "Collector /metrics probe:" >&2
        collector_metrics_probe >&2
        echo "Collector /metrics size:" >&2
        collector_metrics_size >&2
        if [ -n "${LOG_PATH:-}" ] && [ -f "${LOG_PATH}" ]; then
          echo "KMS log tail:" >&2
          if ! tail -n 200 "${LOG_PATH}" >&2; then
            echo "Failed to read KMS log: ${LOG_PATH}" >&2
          fi
        fi
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
        if ! curl_clean_env -sS -D - "${OTEL_EXPORT_SCRAPE_URL}" -o /dev/null >&2; then
          echo "Failed to fetch collector headers from: ${OTEL_EXPORT_SCRAPE_URL}" >&2
        fi
        echo "Collector /metrics probe:" >&2
        collector_metrics_probe >&2
        echo "Collector /metrics size:" >&2
        collector_metrics_size >&2
        if [ -n "${LOG_PATH:-}" ] && [ -f "${LOG_PATH}" ]; then
          echo "KMS log tail:" >&2
          if ! tail -n 200 "${LOG_PATH}" >&2; then
            echo "Failed to read KMS log: ${LOG_PATH}" >&2
          fi
        fi
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
  require_cmd curl "curl is required to scrape the collector metrics endpoint. Install it and retry."

  echo "========================================="
  echo "Running OTEL export integration test"
  echo "========================================="

  trap cleanup EXIT

  echo "Starting KMS server (background)..."

  # Collector containers are started outside of this script; just wait for the
  # Prometheus scrape endpoint to respond.
  wait_for_collector_http_endpoint

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
  rm -f "${LOG_PATH}"

  echo "Building KMS server (may take a while on cold caches)..."
  # Build first so the readiness wait doesn't time out while `cargo run` is compiling.
  # shellcheck disable=SC2086
  cargo build -p cosmian_kms_server $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --bin cosmian_kms

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
      if ! tail -n 200 /tmp/kms-otel-export.log >&2; then
        echo "Failed to read KMS log: /tmp/kms-otel-export.log" >&2
      fi
      exit 1
    fi

    # New-style success responses are `CreateResponse` with a top-level `value` array.
    if echo "${resp}" | grep -q '^Invalid Request:'; then
      echo "Create failed (iteration ${i}):" >&2
      echo "${resp}" >&2
      echo "KMS log tail:" >&2
      if ! tail -n 200 /tmp/kms-otel-export.log >&2; then
        echo "Failed to read KMS log: /tmp/kms-otel-export.log" >&2
      fi
      exit 1
    fi
    uid=$(printf '%s' "${resp}" | extract_uid)
    if [ -z "${uid}" ]; then
      echo "Failed to parse unique identifier from Create response (iteration ${i})." >&2
      echo "Response was: ${resp}" >&2
      echo "KMS log tail:" >&2
      if ! tail -n 200 /tmp/kms-otel-export.log >&2; then
        echo "Failed to read KMS log: /tmp/kms-otel-export.log" >&2
      fi
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

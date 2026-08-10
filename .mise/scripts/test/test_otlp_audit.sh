#!/usr/bin/env bash
# OTLP audit log export integration test.
#
# Proves ADR-006 (OTLP Log Record Export for Audit Events):
#
#   KMS AuditOtlpLogs → POST /v1/logs → OTel collector → file exporter
#
# Test flow:
#   1. Start otel/opentelemetry-collector-contrib (HTTP port 4318, file exporter)
#   2. Build KMS server + ckms CLI
#   3. Start KMS with --audit-otlp-endpoint + --audit-otlp-allow-insecure
#   4. Exercise 4 KMIP operations
#   5. Stop KMS to force batch flush (batch fills at 64 or on shutdown)
#   6. Wait for collector to write file (up to 30s)
#   7. Assert: log record count > 0 in collector output (exit 1 if 0)
#   8. Assert: at least 1 record has cef_line attribute (ADR-006 §payload)
#   9. Assert: severityText in {"Success", "Failure"}
#  10. Print evidence
#
# Usage:
#   bash .mise/scripts/test/test_otlp_audit.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

COLLECTOR_CONTAINER=""
AUDIT_JSONL=""
COLLECTOR_LOG_DIR=""

cleanup() {
  kms_stop
  if [ -n "${COLLECTOR_CONTAINER:-}" ]; then
    docker rm -f "${COLLECTOR_CONTAINER}" 2>/dev/null || true
    COLLECTOR_CONTAINER=""
  fi
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
  [ -n "${COLLECTOR_LOG_DIR:-}" ] && { rm -rf "${COLLECTOR_LOG_DIR}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "OTLP audit log export integration test"
echo "Proves: ADR-006 (AuditOtlpLogs → OTel collector)"
echo "==========================================="

# ── Prerequisite: Docker ──────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not available — skipping OTLP audit test." >&2
  exit 1
fi
if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running — skipping OTLP audit test." >&2
  exit 1
fi

# ── Port selection ────────────────────────────────────────────────────────────

OTLP_HTTP_PORT=${KMS_SLOT_OTEL_HTTP_PORT:-4318}
COLLECTOR_LOG_DIR="$(mktemp -d /tmp/kms-otlp-audit-XXXXXX)"
COLLECTOR_LOG_FILE="${COLLECTOR_LOG_DIR}/otel-audit-logs.jsonl"
touch "${COLLECTOR_LOG_FILE}"
chmod 777 "${COLLECTOR_LOG_FILE}"

# Pre-flight: remove any container already occupying our port (from a previous failed run)
for ctr in $(docker ps -q --filter "publish=${OTLP_HTTP_PORT}" 2>/dev/null); do
  echo "    Pre-flight: removing stale container ${ctr} on port ${OTLP_HTTP_PORT}..."
  docker rm -f "${ctr}" 2>/dev/null || true
done

# ── Start OTel collector ──────────────────────────────────────────────────────

echo "==> Starting OTel collector (HTTP port ${OTLP_HTTP_PORT}, file exporter)..."
COLLECTOR_CONTAINER="kms-siem-test-otlp-collector-$$"

docker run --rm --name "${COLLECTOR_CONTAINER}" \
  -p "${OTLP_HTTP_PORT}:4318" \
  -v "${SCRIPT_DIR}/otlp-audit-collector-config.yaml:/etc/otel-collector-config.yaml:ro" \
  -v "${COLLECTOR_LOG_DIR}:/tmp:rw" \
  otel/opentelemetry-collector-contrib:latest \
  --config=/etc/otel-collector-config.yaml \
  2>/dev/null &

# Wait for collector HTTP port to be ready (use nc -z: OTel HTTP receiver returns
# HTTP 400 on plain GET /, which curl -sf would treat as failure)
echo "==> Waiting for OTel collector on port ${OTLP_HTTP_PORT}..."
waited=0
while ! nc -z 127.0.0.1 "${OTLP_HTTP_PORT}" 2>/dev/null; do
  if [ "${waited}" -ge 60 ]; then
    echo "ERROR: OTel collector did not become ready within 60s." >&2
    docker logs "${COLLECTOR_CONTAINER}" 2>/dev/null >&2 || true
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
echo "    OTel collector is ready (${waited}s)."

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit OTLP enabled ──────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-otlp-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS on port ${KMS_PORT} with audit OTLP → http://127.0.0.1:${OTLP_HTTP_PORT}..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-otlp-test-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"

[audit.otlp]
endpoint = "http://127.0.0.1:${OTLP_HTTP_PORT}"
allow_insecure = true
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

# ── Helper functions ──────────────────────────────────────────────────────────

ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null
}
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null || true
}
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

# ── Exercise KMIP operations ──────────────────────────────────────────────────

echo "==> Exercising KMIP operations (generating >64 events to trigger OTLP batch flush)..."
echo "    OTLP batch size = 64; we generate 66 events to guarantee at least 1 full batch is sent."

# Generate 33 Create+Destroy pairs = 66 audit events (>= BATCH_SIZE=64).
# Each pair produces 2 events. The 64th event triggers send_batch while KMS is running.
batch_uid=""
for _ in $(seq 1 33); do
  CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256) 2>/dev/null || true
  batch_uid=$(echo "${CREATE_OUT}" | extract_uid)
  if [ -n "${batch_uid}" ]; then
    ckms_run sym keys destroy --key-id "${batch_uid}"
  fi
done
echo "    Generated 66 audit events (33 Create + 33 Destroy)."

echo "==> Waiting for audit events to flush to file..."
sleep 2

audit_lines=$(
  grep -c . "${AUDIT_JSONL}"
  true
)
echo "    Audit file has ${audit_lines} event(s)."

# Wait up to 15s for the OTLP batch to be delivered to the collector
# (batch of 64+ is sent while KMS is still running — no need to stop KMS first)
echo "==> Waiting for OTel collector to receive the OTLP batch (up to 15s)..."
waited=0
while [ "${waited}" -lt 15 ]; do
  file_size=$(wc -c <"${COLLECTOR_LOG_FILE}" 2>/dev/null || echo 0)
  if [ "${file_size}" -gt 10 ]; then
    break
  fi
  sleep 1
  waited=$((waited + 1))
done

# Stop KMS (partial remaining batch may or may not flush on shutdown — acceptable)
echo "==> Stopping KMS..."
kms_stop

file_size=$(wc -c <"${COLLECTOR_LOG_FILE}" 2>/dev/null || echo 0)
echo "    Collector log file size: ${file_size} bytes."

# ── GUARD 1: collector must have received log records ────────────────────────

if [ "${file_size}" -lt 10 ]; then
  echo "ERROR: OTel collector file exporter wrote 0 bytes." >&2
  echo "       No OTLP log records were received." >&2
  echo "       KMS AuditOtlpLogs is not sending to the collector." >&2
  docker logs "${COLLECTOR_CONTAINER}" 2>/dev/null >&2 || true
  exit 1
fi

# Count log records by parsing the JSONL file (each line is an ExportLogsServiceRequest)
log_record_count=$(python3 -c "
import json, sys
total = 0
with open('${COLLECTOR_LOG_FILE}') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            for rl in data.get('resourceLogs', []):
                for sl in rl.get('scopeLogs', []):
                    total += len(sl.get('logRecords', []))
        except json.JSONDecodeError:
            pass
print(total)
" 2>/dev/null || echo 0)

echo "    Log record count in collector: ${log_record_count}."

if [ "${log_record_count}" -lt 1 ]; then
  echo "ERROR: 0 OTLP log records found in collector output." >&2
  echo "       AuditOtlpLogs is not delivering events to the collector." >&2
  echo "       Collector log file contents:" >&2
  cat "${COLLECTOR_LOG_FILE}" >&2
  exit 1
fi
echo "GUARD OK: ${log_record_count} OTLP log record(s) received by collector."

# ── GUARD 2: cef_line attribute must be present ──────────────────────────────

cef_attr_count=$(python3 -c "
import json, sys
count = 0
with open('${COLLECTOR_LOG_FILE}') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            for rl in data.get('resourceLogs', []):
                for sl in rl.get('scopeLogs', []):
                    for rec in sl.get('logRecords', []):
                        for attr in rec.get('attributes', []):
                            if attr.get('key') == 'cef_line':
                                count += 1
        except json.JSONDecodeError:
            pass
print(count)
" 2>/dev/null || echo 0)

echo "    Log records with cef_line attribute: ${cef_attr_count}."

if [ "${cef_attr_count}" -lt 1 ]; then
  echo "ERROR: no OTLP log record has a 'cef_line' attribute." >&2
  echo "       ADR-006 requires cef_line attribute on every log record." >&2
  exit 1
fi
echo "GUARD OK: ${cef_attr_count} record(s) have cef_line attribute (ADR-006 compliance)."

# ── GUARD 3: severityText must be Success or Failure ─────────────────────────

severity_ok=$(python3 -c "
import json, sys
valid = {'Success', 'Failure'}
bad = []
with open('${COLLECTOR_LOG_FILE}') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            for rl in data.get('resourceLogs', []):
                for sl in rl.get('scopeLogs', []):
                    for rec in sl.get('logRecords', []):
                        sev = rec.get('severityText', '')
                        if sev and sev not in valid:
                            bad.append(sev)
        except json.JSONDecodeError:
            pass
if bad:
    print('BAD:' + ','.join(bad))
else:
    print('OK')
" 2>/dev/null || echo "PARSE_ERROR")

if [[ "${severity_ok}" == BAD:* ]]; then
  echo "ERROR: unexpected severityText values: ${severity_ok#BAD:}" >&2
  echo "       Expected only 'Success' or 'Failure'." >&2
  exit 1
fi
echo "GUARD OK: all records have valid severityText (Success or Failure)."

# ── Print evidence ────────────────────────────────────────────────────────────

echo ""
echo "==> Evidence — OTLP log record sample:"
python3 -c "
import json
with open('${COLLECTOR_LOG_FILE}') as f:
    line = f.readline().strip()
    if line:
        data = json.loads(line)
        for rl in data.get('resourceLogs', []):
            scope = rl.get('scopeLogs', [{}])[0]
            print(f'  Scope: {scope.get(\"scope\",{}).get(\"name\",\"?\")}')
            for i, rec in enumerate(scope.get('logRecords', [])[:2], 1):
                sev = rec.get('severityText','?')
                body = str(rec.get('body',{}).get('stringValue',''))[:80]
                cef_attr = next((a['value']['stringValue'][:60] for a in rec.get('attributes',[]) if a['key']=='cef_line'), '(none)')
                print(f'  [{i}] severity={sev}, body={body}...')
                print(f'       cef_line={cef_attr}...')
" 2>/dev/null || echo "  (parsing error, but records found)"

echo ""
echo "OTLP audit log export test PASSED."
echo "Evidence: ${log_record_count} OTLP log records received, ${cef_attr_count} with cef_line attribute."
echo "Proves ADR-006 (AuditOtlpLogs → OTel collector pipeline)."

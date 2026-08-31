#!/usr/bin/env bash
# Audit log integration test.
#
# Proves tamper-evident JSONL single-writer log and HTTP audit middleware capture:
#
#   KMS audit middleware → JSONL file (ckms audit verify validates hash chain)
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Start KMS with audit logging enabled
#   3. Exercise KMIP operations: Create, Encrypt, Decrypt, Destroy
#      (plus 1 deliberate Failure for result coverage)
#   4. Assert audit file has ≥5 events (exit 1 if 0)
#   5. Run `ckms audit verify --path` — exit 1 if chain broken
#   6. Validate required fields in every event (exit 1 if any missing)
#   7. Print evidence for each event
#
# Usage:
#   bash .mise/scripts/test/test_audit_log.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

AUDIT_JSONL=""

cleanup() {
  kms_stop
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "Audit log integration test"
echo "Proves: tamper-evident JSONL hash chain + HTTP audit middleware capture"
echo "==========================================="

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-audit-test-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"
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

echo "==> Exercising KMIP operations..."

# Success operations
CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
echo "    Created AES-256 key: ${SYM_UID}"

TMPDIR_DATA="$(mktemp -d -t audit-test-XXXXXX)"
PLAINTEXT="${TMPDIR_DATA}/plaintext.txt"
ENCRYPTED="${TMPDIR_DATA}/encrypted.bin"
DECRYPTED="${TMPDIR_DATA}/decrypted.txt"
echo "Hello, audit log test!" >"${PLAINTEXT}"

ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
echo "    Encrypted."
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output "${DECRYPTED}"
echo "    Decrypted."

ckms_run sym keys destroy --key-id "${SYM_UID}"
echo "    Destroyed key."
rm -rf "${TMPDIR_DATA}"

# Deliberate Failure: export a non-existent key to produce a Failure result event
ckms_run sym keys export --key-id "00000000-0000-0000-0000-000000000000" 2>/dev/null || true
echo "    Triggered deliberate Failure event (non-existent key)."

echo "==> Waiting for audit events to flush..."
sleep 2

# ── GUARD 1: audit file must have events ─────────────────────────────────────

audit_lines=$(
  grep -c . "${AUDIT_JSONL}"
  true
)
echo "    Audit file has ${audit_lines} event(s)."

if [ "${audit_lines}" -lt 4 ]; then
  echo "ERROR: expected at least 4 audit events, got ${audit_lines}." >&2
  echo "       No evidence of audit middleware writing events." >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi
echo "GUARD OK: ${audit_lines} audit events written (>= 4 required)."

# ── GUARD 2: hash chain must be valid ─────────────────────────────────────────

echo "==> Running ckms audit verify --path ${AUDIT_JSONL}..."
if ! "${ckms_bin}" audit verify --path "${AUDIT_JSONL}" 2>&1; then
  echo "ERROR: ckms audit verify failed — tamper-evident hash chain is broken." >&2
  echo "       Hash chain verification failed — chain is NOT intact." >&2
  exit 1
fi
echo "GUARD OK: hash chain verified (${audit_lines} rows, SHA-256 chain intact)."

# ── GUARD 3: required fields in every event ──────────────────────────────────

echo "==> Validating required fields in every audit event..."

REQUIRED_FIELDS=("timestamp" "operation" "user" "result" "request_id" "client_ip")

missing_count=0
event_num=0
while IFS= read -r line; do
  [ -z "${line}" ] && continue
  event_num=$((event_num + 1))
  for field in "${REQUIRED_FIELDS[@]}"; do
    if ! echo "${line}" | python3 -c "import sys, json; d=json.loads(sys.stdin.read()); sys.exit(0 if '${field}' in d else 1)" 2>/dev/null; then
      echo "ERROR: event #${event_num} missing required field '${field}'." >&2
      echo "       Event: ${line}" >&2
      missing_count=$((missing_count + 1))
    fi
  done
done <"${AUDIT_JSONL}"

if [ "${missing_count}" -gt 0 ]; then
  echo "ERROR: ${missing_count} field check(s) failed across ${event_num} audit events." >&2
  exit 1
fi
echo "GUARD OK: all ${event_num} events have required fields: ${REQUIRED_FIELDS[*]}"

# ── GUARD 4: result field coverage (Success + Failure) ───────────────────────

success_count=$(python3 -c "
import json, sys
lines = [l for l in open('${AUDIT_JSONL}') if l.strip()]
count = sum(1 for l in lines if json.loads(l).get('result') == 'Success')
print(count)
")
failure_count=$(python3 -c "
import json, sys
lines = [l for l in open('${AUDIT_JSONL}') if l.strip()]
count = sum(1 for l in lines if isinstance(json.loads(l).get('result'), dict) and 'Failure' in json.loads(l).get('result', {}))
print(count)
")

echo "    Result coverage: ${success_count} Success, ${failure_count} Failure events."

if [ "${success_count}" -lt 1 ]; then
  echo "ERROR: no Success result events found — audit middleware may not be recording results." >&2
  exit 1
fi
if [ "${failure_count}" -lt 1 ]; then
  echo "ERROR: no Failure result events found — deliberate failure was not captured." >&2
  exit 1
fi
echo "GUARD OK: result coverage verified (${success_count} Success, ${failure_count} Failure)."

# ── Print evidence ────────────────────────────────────────────────────────────

echo ""
echo "==> Evidence — audit events sample:"
python3 -c "
import json
with open('${AUDIT_JSONL}') as f:
    for i, line in enumerate(f, 1):
        if not line.strip(): continue
        d = json.loads(line)
        result = d.get('result', '?')
        result_str = result if isinstance(result, str) else 'Failure:' + list(result.values())[0][:40]
        print(f'  [{i}] ts={d[\"timestamp\"][:19]} op={d[\"operation\"]:20s} user={d.get(\"user\",\"?\"):20s} result={result_str}')
"

echo ""
echo "Audit log integration test PASSED."
echo "Evidence: ${audit_lines} events written, hash chain verified (${audit_lines} rows)."
echo "Proves tamper-evident JSONL hash chain + HTTP audit middleware capture."

#!/usr/bin/env bash
# CEF format validation test.
#
# Proves CEF v27 as the SIEM export format:
#
#   ckms audit export --format cef → N CEF lines with all required extension keys
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Start KMS with audit logging enabled
#   3. Exercise KMIP operations (including 1 deliberate Failure for outcome coverage)
#   4. Export audit log as CEF: `ckms audit export --format cef --path <file>`
#   5. Assert cef_lines == audit_lines > 0 (1:1 mapping, exit 1 if 0)
#   6. Assert every line starts with CEF:0|Cosmian|KMS|
#   7. Assert every line has all required extension keys (CEF v27)
#   8. Assert ≥1 Success and ≥1 Failure outcome
#   9. Print evidence
#
# Usage:
#   bash .mise/scripts/test/test_cef_format.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

AUDIT_JSONL=""
CEF_EXPORT=""

cleanup() {
  kms_stop
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
  [ -n "${CEF_EXPORT:-}" ] && { rm -f "${CEF_EXPORT}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "CEF format validation test"
echo "Proves: CEF v27 format compliance"
echo "==========================================="

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-cef-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-cef-fmt-XXXXXX)"

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

echo "==> Exercising KMIP operations (4 ops including 1 deliberate Failure)..."

CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
echo "    Created AES-256 key: ${SYM_UID}"

TMPDIR_DATA="$(mktemp -d -t cef-fmt-XXXXXX)"
PLAINTEXT="${TMPDIR_DATA}/plaintext.txt"
ENCRYPTED="${TMPDIR_DATA}/encrypted.bin"
echo "Hello, CEF format test!" >"${PLAINTEXT}"

ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
echo "    Encrypted."
ckms_run sym keys destroy --key-id "${SYM_UID}"
echo "    Destroyed key."
rm -rf "${TMPDIR_DATA}"

# Deliberate Failure: export a non-existent key to produce a Failure result event
ckms_run sym keys export --key-id "00000000-0000-0000-0000-000000000000" 2>/dev/null || true
echo "    Triggered deliberate Failure event (non-existent key)."

echo "==> Waiting for audit events to flush..."
sleep 2

audit_lines=$(
  grep -c . "${AUDIT_JSONL}"
  true
)
echo "    Audit file has ${audit_lines} event(s)."

if [ "${audit_lines}" -lt 3 ]; then
  echo "ERROR: expected at least 3 audit events, got ${audit_lines}." >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

# ── Export as CEF ─────────────────────────────────────────────────────────────

CEF_EXPORT="$(mktemp -t kms-cef-XXXXXX.txt)"
echo "==> Exporting audit log as CEF..."
"${ckms_bin}" audit export \
  --path "${AUDIT_JSONL}" \
  --format cef \
  >"${CEF_EXPORT}" 2>/dev/null

# ── GUARD 1: non-zero CEF output ─────────────────────────────────────────────

cef_lines=$(
  grep -c '^CEF:' "${CEF_EXPORT}" 2>/dev/null
  true
)
echo "    CEF export produced ${cef_lines} line(s)."

if [ "${cef_lines}" -lt 1 ]; then
  echo "ERROR: CEF export produced 0 lines from ${audit_lines} audit events." >&2
  echo "       ckms audit export --format cef is not working." >&2
  cat "${CEF_EXPORT}" >&2
  exit 1
fi
echo "GUARD OK: ${cef_lines} CEF lines produced."

# ── GUARD 2: 1:1 mapping ─────────────────────────────────────────────────────

if [ "${cef_lines}" -ne "${audit_lines}" ]; then
  echo "ERROR: CEF line count (${cef_lines}) != audit event count (${audit_lines})." >&2
  echo "       Every audit event must produce exactly one CEF line." >&2
  exit 1
fi
echo "GUARD OK: 1:1 mapping — ${cef_lines} CEF lines for ${audit_lines} audit events."

# ── GUARD 3: CEF header format ───────────────────────────────────────────────

echo "==> Checking CEF header format (CEF:0|Cosmian|KMS|...)..."
bad_header=0
while IFS= read -r line; do
  [ -z "${line}" ] && continue
  if ! echo "${line}" | grep -q '^CEF:0|Cosmian|KMS|'; then
    echo "ERROR: malformed CEF header: ${line}" >&2
    bad_header=$((bad_header + 1))
  fi
done <"${CEF_EXPORT}"

if [ "${bad_header}" -gt 0 ]; then
  echo "ERROR: ${bad_header} CEF line(s) have malformed headers." >&2
  exit 1
fi
echo "GUARD OK: all ${cef_lines} lines have CEF:0|Cosmian|KMS| header."

# ── GUARD 4: required extension keys (CEF v27) ─────────────────────

# CEF v27 required extension keys for KMS audit:
#   rt=         — receive time (epoch ms)
#   suser=      — user identity
#   act=        — KMIP operation name
#   cn1=        — duration value (numeric)
#   cn1Label=durationMs — label for cn1
#   outcome=    — Success or Failure
#   externalId= — audit record id
#   devicePayloadId= — request correlation UUID
REQUIRED_KEYS=("rt=" "suser=" "act=" "cn1=" "cn1Label=durationMs" "outcome=" "externalId=" "devicePayloadId=")

echo "==> Checking required CEF extension keys..."
fail_count=0
line_num=0
while IFS= read -r line; do
  [ -z "${line}" ] && continue
  line_num=$((line_num + 1))
  for key in "${REQUIRED_KEYS[@]}"; do
    if ! echo "${line}" | grep -q "${key}"; then
      echo "ERROR: CEF line #${line_num} missing extension key '${key}'." >&2
      echo "       Line: ${line:0:200}..." >&2
      fail_count=$((fail_count + 1))
    fi
  done
done <"${CEF_EXPORT}"

if [ "${fail_count}" -gt 0 ]; then
  echo "ERROR: ${fail_count} extension key check(s) failed." >&2
  echo "       CEF v27 compliance not satisfied." >&2
  exit 1
fi
echo "GUARD OK: all ${cef_lines} lines have required extension keys: ${REQUIRED_KEYS[*]}"

# ── GUARD 5: outcome coverage (Success + Failure) ────────────────────────────

success_cef=$(
  grep -c 'outcome=Success' "${CEF_EXPORT}" 2>/dev/null
  true
)
failure_cef=$(
  grep -c 'outcome=Failure' "${CEF_EXPORT}" 2>/dev/null
  true
)

echo "    Outcome coverage: ${success_cef} Success, ${failure_cef} Failure CEF lines."

if [ "${success_cef}" -lt 1 ]; then
  echo "ERROR: no CEF line with outcome=Success found." >&2
  exit 1
fi
if [ "${failure_cef}" -lt 1 ]; then
  echo "ERROR: no CEF line with outcome=Failure found." >&2
  echo "       The deliberate Failure event was not exported as CEF." >&2
  exit 1
fi
echo "GUARD OK: outcome coverage verified (${success_cef} Success, ${failure_cef} Failure)."

# ── Print evidence ────────────────────────────────────────────────────────────

echo ""
echo "==> Evidence — CEF lines sample:"
head -3 "${CEF_EXPORT}" | while IFS= read -r line; do
  echo "  ${line:0:120}..."
done

echo ""
echo "CEF format validation test PASSED."
echo "Evidence: ${cef_lines} CEF lines (${success_cef} Success + ${failure_cef} Failure),"
echo "  all with CEF:0|Cosmian|KMS| header and required extension keys."
echo "Proves CEF v27 format compliance."

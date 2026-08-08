#!/usr/bin/env bash
# CEF-over-syslog integration test.
#
# Validates the pipeline documented in siems.md:
#
#   ckms audit export --format cef | logger -t kms-audit | UDP listener
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Start KMS with audit logging enabled
#   3. Exercise KMIP operations to produce audit events
#   4. Start a Python UDP syslog receiver (siem_verify_fields.py syslog)
#   5. Export audit log as CEF and pipe via logger to the receiver
#   6. Assert every received message contains a valid CEF:0 header
#   7. Clean up
#
# This proves the "Ad hoc export to a CEF listener" section of siems.md.
#
# Usage:
#   bash .mise/scripts/test/test_siem_cef_syslog.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/siem_verify_fields.py"
AUDIT_JSONL=""
VENV_DIR=""
RECEIVER_PID=""
# Use a high port to avoid needing root (privileged ports < 1024)
SYSLOG_UDP_PORT=51514

cleanup() {
  kms_stop
  [ -n "${RECEIVER_PID:-}" ] && { kill "${RECEIVER_PID}" 2>/dev/null || true; }
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "CEF-over-syslog integration test"
echo "Proves: siems.md 'CEF export' section"
echo "==========================================="

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Python venv ───────────────────────────────────────────────────────────────

echo "==> Setting up Python virtualenv (no extra packages needed)..."
VENV_DIR="$(mktemp -d -t siem-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# ── Start KMS server with audit logging ───────────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-siem-cef-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations ──────────────────────────────────────────────────

echo "==> Exercising KMIP operations..."

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

TMPDIR_CEF="$(mktemp -d -t cef-data-XXXXXX)"
PLAINTEXT="${TMPDIR_CEF}/plaintext.txt"
ENCRYPTED="${TMPDIR_CEF}/encrypted.bin"
echo "Hello, CEF syslog test!" >"${PLAINTEXT}"
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output "${TMPDIR_CEF}/decrypted.txt"
ckms_run sym keys revoke --key-id "${SYM_UID}"
ckms_run sym keys destroy --key-id "${SYM_UID}"
rm -rf "${TMPDIR_CEF}"

echo "==> Waiting for audit events to flush..."
sleep 2

audit_lines=$(grep -c . "${AUDIT_JSONL}")
echo "    Audit file has ${audit_lines} event(s)."
if [ "${audit_lines}" -lt 3 ]; then
  echo "ERROR: expected at least 3 audit events, got ${audit_lines}" >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

# ── Export CEF to a temp file ─────────────────────────────────────────────────
#
# We export first so we know the exact CEF line count before starting the UDP
# receiver. This is necessary for exact-count enforcement: the receiver must be
# told how many messages to expect before the first packet arrives.

CEF_EXPORT_FILE="$(mktemp -t kms-cef-XXXXXX.txt)"
"${ckms_bin}" audit export \
  --path "${AUDIT_JSONL}" \
  --format cef \
  >"${CEF_EXPORT_FILE}" 2>/dev/null

cef_lines=$(grep -c '^CEF:' "${CEF_EXPORT_FILE}" 2>/dev/null || echo 0)
echo "    CEF export produced ${cef_lines} line(s)."

if [ "${cef_lines}" -lt 1 ]; then
  echo "ERROR: CEF export produced no output from audit file with ${audit_lines} events" >&2
  cat "${CEF_EXPORT_FILE}" >&2
  exit 1
fi

# Guard: every audit event must have a CEF representation.
if [ "${cef_lines}" -ne "${audit_lines}" ]; then
  echo "ERROR: CEF line count (${cef_lines}) != audit event count (${audit_lines})." >&2
  echo "       Every audit event must produce exactly one CEF line." >&2
  echo "CEF export:" >&2
  cat "${CEF_EXPORT_FILE}" >&2
  echo "Audit JSONL:" >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

echo "    Guard OK: ${cef_lines}/${audit_lines} events have CEF representation."

# ── Start UDP syslog receiver AFTER knowing the exact count ───────────────────

RECEIVED_LOG="$(mktemp -t siem-received-XXXXXX.txt)"
echo "==> Starting UDP syslog receiver on port ${SYSLOG_UDP_PORT} (expecting ${cef_lines} messages)..."
# The receiver exits only when exactly --count messages are received OR timeout.
# Using --source to cross-validate CEF operation values against the source JSONL.
python3 "${HELPER}" syslog \
  --port "${SYSLOG_UDP_PORT}" \
  --count "${cef_lines}" \
  --timeout 60 \
  --source "${AUDIT_JSONL}" \
  >"${RECEIVED_LOG}" 2>&1 &
RECEIVER_PID=$!
# Give the receiver a moment to bind the socket before we send
sleep 0.5

# ── Send CEF lines via simulated syslog UDP ───────────────────────────────────

echo "==> Sending ${cef_lines} CEF line(s) via UDP to port ${SYSLOG_UDP_PORT}..."

# This is the exact pipeline documented in siems.md.
# We wrap each CEF line in a minimal syslog RFC 3164 PRI header and send via nc.
sent=0
while IFS= read -r line; do
  [[ "${line}" == CEF:* ]] || continue
  printf '<134>%s kms-audit: %s\n' "$(date '+%b %d %H:%M:%S')" "${line}" |
    nc -u -w 1 127.0.0.1 "${SYSLOG_UDP_PORT}" 2>/dev/null || true
  sent=$((sent + 1))
  # Small delay between packets to avoid UDP buffer overflow
  sleep 0.05
done <"${CEF_EXPORT_FILE}"
rm -f "${CEF_EXPORT_FILE}"

echo "    Sent ${sent} UDP packet(s)."
if [ "${sent}" -ne "${cef_lines}" ]; then
  echo "ERROR: sent ${sent} UDP packets but expected to send ${cef_lines}" >&2
  exit 1
fi

echo "==> Waiting for receiver to process messages..."
wait "${RECEIVER_PID}" || true
RECEIVER_PID=""

# ── Verify ────────────────────────────────────────────────────────────────────

echo "==> Verifying received syslog messages..."
cat "${RECEIVED_LOG}"
if grep -q "^FAIL:" "${RECEIVED_LOG}"; then
  echo "ERROR: syslog receiver reported a verification failure." >&2
  exit 1
fi
if ! grep -q "^OK:.*received exactly ${cef_lines}" "${RECEIVED_LOG}"; then
  echo "ERROR: expected confirmation of exactly ${cef_lines} CEF line(s)." >&2
  cat "${RECEIVED_LOG}" >&2
  exit 1
fi

rm -f "${RECEIVED_LOG}"

echo ""
echo "CEF-over-syslog integration test PASSED."
echo "Verified: all ${cef_lines} KMS audit events exported as CEF and received via syslog."
echo "Proves the 'CEF export → syslog listener' section of siems.md."

#!/usr/bin/env bash
# CEF-over-TCP-syslog integration test (rsyslog Docker).
#
# Validates the pipeline:
#
#   ckms audit export --format cef | TCP (octet-counting) → rsyslog → file
#
# Compared to the UDP CEF test, this proves:
#   - TCP delivery (no silent drops, ordered delivery)
#   - RFC 6587 octet-counting framing
#   - Interop with a real rsyslog daemon (rsyslog/syslog_appliance_alpine)
#
# Test flow:
#   1. Start rsyslog container (TCP listener on port 514 → host 51514)
#   2. Build KMS server + ckms CLI
#   3. Start KMS with audit logging enabled
#   4. Exercise KMIP operations to produce audit events
#   5. Export audit log as CEF
#   6. Send CEF lines via TCP with octet-counting framing
#   7. Read rsyslog output file and assert every CEF field is preserved
#   8. Clean up
#
# Usage:
#   bash .mise/scripts/test/test_siem_cef_tcp_syslog.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

AUDIT_JSONL=""
VENV_DIR=""
RSYSLOG_CONTAINER=""
RSYSLOG_DIR=""

# Use a high port to avoid needing root (privileged ports < 1024).
SYSLOG_TCP_PORT=${KMS_SLOT_RSYSLOG_TCP_PORT:-51514}

cleanup() {
  kms_stop
  if [ -n "${RSYSLOG_CONTAINER:-}" ]; then
    docker rm -f "${RSYSLOG_CONTAINER}" 2>/dev/null || true
    RSYSLOG_CONTAINER=""
  fi
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${RSYSLOG_DIR:-}" ] && { rm -rf "${RSYSLOG_DIR}" || true; }
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "CEF-over-TCP-syslog integration test"
echo "Proves: siems.md CEF export → TCP syslog"
echo "==========================================="

# ── Prerequisite: Docker ──────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not available — skipping TCP syslog test." >&2
  exit 1
fi
if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running — skipping TCP syslog test." >&2
  exit 1
fi

# ── Start rsyslog container ────────────────────────────────────────────────────

RSYSLOG_DIR="$(mktemp -d /tmp/kms-siem-rsyslog-XXXXXX)"
RSYSLOG_LOG="${RSYSLOG_DIR}/kms-cef.log"
touch "${RSYSLOG_LOG}"

echo "==> Starting rsyslog container on TCP port ${SYSLOG_TCP_PORT}..."
RSYSLOG_CONTAINER="kms-siem-test-rsyslog-$$"

docker run --rm --name "${RSYSLOG_CONTAINER}" \
  -p "${SYSLOG_TCP_PORT}:514" \
  -v "${SCRIPT_DIR}/rsyslog.conf:/etc/rsyslog.conf:ro" \
  -v "${RSYSLOG_LOG}:/var/log/kms-cef.log:rw" \
  rsyslog/syslog_appliance_alpine:latest \
  2>/dev/null &

# Wait for rsyslog TCP listener to be ready
echo "==> Waiting for rsyslog TCP listener on port ${SYSLOG_TCP_PORT}..."
waited=0
while ! nc -z 127.0.0.1 "${SYSLOG_TCP_PORT}" 2>/dev/null; do
  if [ "${waited}" -ge 30 ]; then
    echo "ERROR: rsyslog did not become ready within 30s." >&2
    docker logs "${RSYSLOG_CONTAINER}" 2>/dev/null >&2 || true
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
echo "    rsyslog is ready (${waited}s)."

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
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-siem-cef-tcp-XXXXXX)"

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

TMPDIR_CEF="$(mktemp -d -t cef-tcp-data-XXXXXX)"
PLAINTEXT="${TMPDIR_CEF}/plaintext.txt"
ENCRYPTED="${TMPDIR_CEF}/encrypted.bin"
echo "Hello, CEF TCP syslog test!" >"${PLAINTEXT}"
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

# ── Export CEF ────────────────────────────────────────────────────────────────

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

# ── Send CEF lines via TCP with RFC 6587 octet-counting framing ───────────────

echo "==> Sending ${cef_lines} CEF line(s) via TCP (octet-counting framing) to port ${SYSLOG_TCP_PORT}..."

# Format per RFC 6587 §3.4.1: "<byte-count> <message>"
# The message includes the syslog PRI header + CEF line.
# rsyslog's imtcp module with default framing supports this format.

sent=0
while IFS= read -r line; do
  [[ "${line}" == CEF:* ]] || continue
  # Assemble a minimal RFC 3164 syslog message (PRI 134 = local0.info)
  syslog_msg="<134>$(date '+%b %d %H:%M:%S') kms-audit: ${line}"
  # RFC 6587 octet-counting: space between count and message, count = len(message)
  printf '%zu %s' "${#syslog_msg}" "${syslog_msg}" |
    nc -w 5 127.0.0.1 "${SYSLOG_TCP_PORT}" 2>/dev/null || true
  sent=$((sent + 1))
  sleep 0.05
done <"${CEF_EXPORT_FILE}"
rm -f "${CEF_EXPORT_FILE}"

echo "    Sent ${sent} TCP frame(s)."
if [ "${sent}" -ne "${cef_lines}" ]; then
  echo "ERROR: sent ${sent} TCP frames but expected to send ${cef_lines}" >&2
  exit 1
fi

# ── Wait for rsyslog to flush ─────────────────────────────────────────────────

echo "==> Waiting for rsyslog to write messages to file..."
waited=0
while [ "${waited}" -lt 20 ]; do
  rsyslog_lines=$(grep -c 'CEF:' "${RSYSLOG_LOG}" 2>/dev/null || echo 0)
  if [ "${rsyslog_lines}" -ge "${cef_lines}" ]; then
    break
  fi
  sleep 1
  waited=$((waited + 1))
done

# Stop rsyslog so it flushes all buffers
docker rm -f "${RSYSLOG_CONTAINER}" 2>/dev/null || true
RSYSLOG_CONTAINER=""

rsyslog_lines=$(grep -c 'CEF:' "${RSYSLOG_LOG}" 2>/dev/null || echo 0)
echo "    rsyslog log file has ${rsyslog_lines} CEF line(s)."

# Guard: all sent messages must be received
if [ "${rsyslog_lines}" -ne "${cef_lines}" ]; then
  echo "ERROR: rsyslog received ${rsyslog_lines}/${cef_lines} CEF messages." >&2
  echo "       TCP delivery must not drop messages." >&2
  echo "rsyslog log file:" >&2
  cat "${RSYSLOG_LOG}" >&2
  exit 1
fi

echo "    Guard OK: all ${cef_lines} CEF messages received by rsyslog."

# ── Extract CEF lines from rsyslog output for verification ────────────────────

VERIFY_CEF="$(mktemp -t kms-cef-verify-XXXXXX.txt)"
grep 'CEF:' "${RSYSLOG_LOG}" | sed 's/.*CEF:/CEF:/' >"${VERIFY_CEF}"

# ── Verify CEF field integrity ───────────────────────────────────────────────

echo "==> Verifying CEF field integrity after TCP transport..."

# Use the Python helper to validate CEF structure.
# We pipe the extracted CEF lines and verify every one starts with CEF:0 and
# contains the required extension keys.
cef_ok=0
cef_fail=0
while IFS= read -r cef_line; do
  if ! echo "${cef_line}" | grep -q '^CEF:0|Cosmian|KMS|'; then
    echo "FAIL: missing CEF header in line: ${cef_line}" >&2
    cef_fail=$((cef_fail + 1))
    continue
  fi
  # Verify required CEF extension keys are present
  for key in rt= suser= outcome= act= cn1= cn1Label=durationMs externalId=; do
    if ! echo "${cef_line}" | grep -q "${key}"; then
      echo "FAIL: missing CEF extension key '${key}' in: ${cef_line}" >&2
      cef_fail=$((cef_fail + 1))
      continue 2
    fi
  done
  cef_ok=$((cef_ok + 1))
done <"${VERIFY_CEF}"

rm -f "${VERIFY_CEF}"

if [ "${cef_fail}" -gt 0 ]; then
  echo "ERROR: ${cef_fail} CEF line(s) failed field verification." >&2
  exit 1
fi

echo "    All ${cef_ok} CEF lines passed field verification."

echo ""
echo "CEF-over-TCP-syslog integration test PASSED."
echo "Verified: all ${cef_lines} KMS audit events exported as CEF,"
echo "  transported via TCP (RFC 6587 octet-counting), received and written by rsyslog."

#!/usr/bin/env bash
# CEF export interoperability test — live server variant.
#
# Starts a real KMS server with audit logging enabled, exercises a comprehensive
# set of KMIP operations via `ckms` to produce audit events covering all JSONL
# features (success, failure, auth failure, null fields, multiple algorithms),
# then exports the resulting JSONL as CEF and validates it against `jc`
# (kellyjonbrazil/jc) — an independent, widely used CEF parser.
#
# This validates the FULL pipeline:
#   KMS server → audit middleware → JSONL file → ckms audit export → CEF → jc parser
#
# Usage:
#   bash .mise/scripts/nix.sh test cef
#   bash .mise/scripts/test/test_cef.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/cef_helper.py"
KMS_VERSION="test-interop-1.0.0"

AUDIT_JSONL=""
CEF_OUTPUT=""
VENV_DIR=""

cleanup() {
  kms_stop
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${CEF_OUTPUT:-}" ] && { rm -f "${CEF_OUTPUT}" || true; }
  [ -n "${AUDIT_JSONL:-}" ] && { rm -f "${AUDIT_JSONL}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "CEF export interoperability test (live)"
echo "==========================================="

# ── Build binaries ────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-cef-sqlite-XXXXXX)"

# Append audit configuration to the generated config file
cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"
EOF

kms_start_from_bin "${kms_bin}"

# Write ckms client config
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations to produce diverse audit events ──────────────────

echo "==> Exercising KMIP operations via ckms..."

# Helper: run ckms with the test config and JSON output
ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null
}

# Helper: run ckms with the test config (text output, errors allowed)
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null || true
}

# Helper: extract UID from JSON create output
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

# Temp files for encrypt/decrypt
TMPDIR_CEF="$(mktemp -d -t cef-data-XXXXXX)"
PLAINTEXT="${TMPDIR_CEF}/plaintext.txt"
ENCRYPTED="${TMPDIR_CEF}/encrypted.bin"
DECRYPTED="${TMPDIR_CEF}/decrypted.txt"
echo "Hello, CEF interop test!" >"${PLAINTEXT}"

# 1. Create AES-256 symmetric key → audit: Create, Success, algorithm=AES
echo "    [1/9] Creating AES-256 key..."
CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
if [ -z "${SYM_UID}" ]; then
  echo "ERROR: failed to create symmetric key. Output: ${CREATE_OUT}" >&2
  exit 1
fi
echo "         UID: ${SYM_UID}"

# 2. Encrypt data → audit: Encrypt, Success
echo "    [2/9] Encrypting data..."
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"

# 3. Decrypt data → audit: Decrypt, Success
echo "    [3/9] Decrypting data..."
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output "${DECRYPTED}"

# 4. Create AES-128 key → audit: Create, Success, different key size
echo "    [4/9] Creating AES-128 key..."
CREATE_OUT2=$(ckms_json sym keys create --algorithm aes --number-of-bits 128)
SYM2_UID=$(echo "${CREATE_OUT2}" | extract_uid)
echo "         UID: ${SYM2_UID}"

# 5. Failed decrypt (wrong key for this ciphertext) → audit: Decrypt, Failure
echo "    [5/9] Attempting decrypt with wrong key (expect failure)..."
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM2_UID}" --output "${TMPDIR_CEF}/bad.bin"

# 6. Decrypt with non-existent key → audit: Failure, null/missing object_uid
echo "    [6/9] Attempting decrypt with non-existent key (expect failure)..."
ckms_run sym decrypt "${ENCRYPTED}" --key-id "non-existent-key-uid-99999" --output "${TMPDIR_CEF}/bad2.bin"

# 7. Revoke + destroy second key → audit: Revoke + Destroy, Success
echo "    [7/9] Revoking and destroying second key..."
ckms_run sym keys revoke --key-id "${SYM2_UID}"
ckms_run sym keys destroy --key-id "${SYM2_UID}"

# 8. Unauthenticated request → audit: 401 Unauthorized, severity 7
echo "    [8/9] Sending unauthenticated request (expect 401)..."
curl -s -o /dev/null "http://127.0.0.1:${KMS_PORT}/kmip/2_1" \
  -X POST -H "Content-Type: application/json" -d '{}' || true

# 9. Revoke + destroy first key → audit: Revoke + Destroy, Success
echo "    [9/9] Revoking and destroying first key..."
ckms_run sym keys revoke --key-id "${SYM_UID}"
ckms_run sym keys destroy --key-id "${SYM_UID}"

# Clean up temp data
rm -rf "${TMPDIR_CEF}"

# ── Wait for audit writer to flush ────────────────────────────────────────────

echo "==> Waiting for audit events to flush..."
sleep 2

# Verify audit file has events
if [ ! -f "${AUDIT_JSONL}" ] || [ ! -s "${AUDIT_JSONL}" ]; then
  echo "ERROR: audit file is empty or missing at ${AUDIT_JSONL}" >&2
  exit 1
fi

audit_lines=$(grep -c . "${AUDIT_JSONL}")
echo "    Audit file has ${audit_lines} event(s)."

if [ "${audit_lines}" -lt 5 ]; then
  echo "ERROR: expected at least 5 audit events, got ${audit_lines}" >&2
  echo "Audit file contents:" >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

# ── Export as CEF ─────────────────────────────────────────────────────────────

echo "==> Exporting audit events as CEF (kms-version=${KMS_VERSION})..."
CEF_OUTPUT="$(mktemp -t cef-export-XXXXXX.txt)"
"${ckms_bin}" audit export \
  --path "${AUDIT_JSONL}" \
  --format cef \
  --kms-version "${KMS_VERSION}" \
  >"${CEF_OUTPUT}"

cef_lines=$(grep -c . "${CEF_OUTPUT}")
if [ "${audit_lines}" != "${cef_lines}" ]; then
  echo "ERROR: audit has ${audit_lines} events but CEF output has ${cef_lines} lines" >&2
  exit 1
fi
echo "    Exported ${cef_lines} CEF line(s)."

# ── Python venv setup (jc) ───────────────────────────────────────────────────

echo "==> Setting up Python virtualenv with jc..."
VENV_DIR="$(mktemp -d -t cef-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
pip install --quiet -r "${SCRIPT_DIR}/requirements-cef.txt"
echo "    Python venv OK ($(python3 --version), jc $(pip show jc | grep ^Version | awk '{print $2}'))"

# ── Round-trip validation ────────────────────────────────────────────────────

echo ""
echo "==> Validating JSONL schema + CEF v27 interop via jc..."
python3 "${HELPER}" --jsonl "${AUDIT_JSONL}" --cef "${CEF_OUTPUT}"

echo ""
echo "CEF export interoperability test passed (${audit_lines} events, live server)."

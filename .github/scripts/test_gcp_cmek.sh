#!/usr/bin/env bash
set -euo pipefail
set -x

# GCP CMEK (Customer Managed Encryption Key) integration test
#
# Validates the end-to-end workflow described in documentation/docs/google_gcp/cmek.md:
#   1. Create a 256-bit symmetric key in the KMS
#   2. Import the RSA wrapping public key (PEM)
#   3. Export the symmetric key wrapped with RSA-AES-Key-Wrap
#   4. Verify the wrapped output size (552 bytes)

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KMS_HOST="127.0.0.1"
KMS_PORT="9998"
KMS_URL="http://${KMS_HOST}:${KMS_PORT}"
KMS_PID=""
LOG_PATH="${LOG_PATH:-/tmp/kms-gcp-cmek.log}"
WRAPPING_KEY_PEM="${REPO_ROOT}/test_data/google_cmek/Import_RSA_AES_WRAP.pem"
WRAPPED_KEY_FILE=""  # set later (temp file)

# Unique identifiers for this test run (avoid collisions with parallel tests)
SYM_KEY_ID="CMEK_Sym_Key_$$"
WRAPPING_KEY_ID="CMEK_Wrapping_Key_$$"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
wait_for_kms() {
  local url="${KMS_URL}/kmip/2_1"
  echo "Waiting for KMS to accept connections at ${url} ..."

  for _ in {1..240}; do
    if [ -n "${KMS_PID}" ] && ! kill -0 "${KMS_PID}" 2>/dev/null; then
      echo "KMS process exited early. Log tail:" >&2
      tail -n 200 "${LOG_PATH}" >&2 || true
      return 1
    fi

    if curl -sS --max-time 2 -o /dev/null -w "%{http_code}" \
      -X POST "${url}" -H "Content-Type: application/json" -d '{}' 2>/dev/null |
      grep -Eq '^[0-9]{3}$'; then
      return 0
    fi

    sleep 0.5
  done

  echo "Timed out waiting for KMS." >&2
  tail -n 200 "${LOG_PATH}" >&2 || true
  return 1
}

cleanup() {
  local status=$?

  if [ -n "${KMS_PID}" ]; then
    if kill -0 "${KMS_PID}" 2>/dev/null; then
      kill "${KMS_PID}" 2>/dev/null || true
      wait "${KMS_PID}" 2>/dev/null || true
    fi
  fi

  # Remove temp files
  [ -n "${WRAPPED_KEY_FILE:-}" ] && rm -f "${WRAPPED_KEY_FILE}"
  [ -n "${SQLITE_PATH:-}" ] && rm -rf "${SQLITE_PATH}"
  [ -n "${KMS_CONF_PATH:-}" ] && rm -f "${KMS_CONF_PATH}"

  return "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "========================================="
echo "Running GCP CMEK tests"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

# Build the server and CLI binaries
# shellcheck disable=SC2086
cargo build -p cosmian_kms_server ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --bin cosmian_kms
# shellcheck disable=SC2086
cargo build -p ckms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

KMS_BIN="${REPO_ROOT}/target/debug/cosmian_kms"
CKMS_BIN="${REPO_ROOT}/target/debug/ckms"

# ---------------------------------------------------------------------------
# Start KMS server
# ---------------------------------------------------------------------------
rm -f "${LOG_PATH}"

SQLITE_PATH="$(mktemp -d -t kms-cmek-sqlite-XXXXXX)"
KMS_CONF_PATH="$(mktemp -t kms-cmek-conf-XXXXXX.toml)"

cat >"${KMS_CONF_PATH}" <<EOF
[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true

[http]
port = ${KMS_PORT}
hostname = "${KMS_HOST}"
EOF

echo "Starting KMS server (background) ..."
RUST_LOG="info,cosmian_kms=debug" \
  "${KMS_BIN}" -c "${KMS_CONF_PATH}" \
  >"${LOG_PATH}" 2>&1 &
KMS_PID=$!

wait_for_kms

# Point the CLI at the running server
export KMS_CLI_URL="${KMS_URL}"
CKMS="${CKMS_BIN} --url ${KMS_URL}"

# ---------------------------------------------------------------------------
# Step 1: Create a 256-bit symmetric key
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 1: Create symmetric key ---"
$CKMS sym keys create --number-of-bits 256 "${SYM_KEY_ID}"

# ---------------------------------------------------------------------------
# Step 2: Import the RSA wrapping public key
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 2: Import RSA wrapping key ---"
[ -f "${WRAPPING_KEY_PEM}" ] || {
  echo "Error: Wrapping key not found at ${WRAPPING_KEY_PEM}" >&2
  exit 1
}
$CKMS rsa keys import --key-format pem --key-usage encrypt --key-usage wrap-key \
  "${WRAPPING_KEY_PEM}" "${WRAPPING_KEY_ID}"

# ---------------------------------------------------------------------------
# Step 3: Export the symmetric key wrapped with RSA-AES-Key-Wrap
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 3: Export wrapped symmetric key ---"
WRAPPED_KEY_FILE="$(mktemp -t cmek-wrapped-XXXXXX.bin)"
$CKMS sym keys export \
  --key-id "${SYM_KEY_ID}" \
  --wrap-key-id "${WRAPPING_KEY_ID}" \
  --key-format raw \
  --wrapping-algorithm rsa-aes-key-wrap \
  "${WRAPPED_KEY_FILE}"

# ---------------------------------------------------------------------------
# Step 4: Verify the wrapped key size
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 4: Verify wrapped key ---"
WRAPPED_SIZE=$(wc -c <"${WRAPPED_KEY_FILE}" | tr -d ' ')
# Expected: 4096 bits (RSA) + 256 bits (AES) + 64 bits (AES-KWP overhead) = 4416 bits = 552 bytes
EXPECTED_SIZE=552

echo "Wrapped key size: ${WRAPPED_SIZE} bytes (expected: ${EXPECTED_SIZE})"

if [ "${WRAPPED_SIZE}" -ne "${EXPECTED_SIZE}" ]; then
  echo "ERROR: Wrapped key size mismatch! Expected ${EXPECTED_SIZE} bytes, got ${WRAPPED_SIZE} bytes." >&2
  exit 1
fi

echo ""
echo "========================================="
echo "GCP CMEK test PASSED"
echo "========================================="

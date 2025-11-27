#!/usr/bin/env bash
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."
require_cmd curl "curl is required for readiness checks and the XKS test client."
require_cmd jq "jq is required by the XKS test client."
require_cmd bash "bash 4.2+ is required by the XKS test client."

KMS_HOST="127.0.0.1"
KMS_PORT="9998"
KMS_URL="https://${KMS_HOST}:${KMS_PORT}"
KMS_PID=""
LOG_PATH="${LOG_PATH:-/tmp/kms-xks.log}"

wait_for_kms_listen() {
  local url="${KMS_URL}/kmip/2_1"
  echo "Waiting for KMS to accept HTTPS connections at ${url} ..."

  for _ in {1..240}; do
    if [ -n "${KMS_PID}" ] && ! kill -0 "${KMS_PID}" 2>/dev/null; then
      echo "KMS process exited early. Log tail:" >&2
      tail -n 200 "${LOG_PATH}" >&2 || true
      return 1
    fi

    # Any HTTP response code means the server is up enough to accept requests.
    if curl -k -sS --max-time 2 -o /dev/null -w "%{http_code}" \
      -X POST "${url}" -H "Content-Type: application/json" -d '{}' 2>/dev/null |
      grep -Eq '^[0-9]{3}$'; then
      return 0
    fi

    sleep 0.5
  done

  echo "Timed out waiting for KMS to accept HTTPS connections." >&2
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

  return "$status"
}
trap cleanup EXIT

echo "========================================="
echo "Running AWS XKS tests"
echo "Variant: ${VARIANT_NAME} | Mode: ${BUILD_PROFILE}"
echo "========================================="

if [ "${VARIANT}" != "non-fips" ]; then
  echo "Error: AWS XKS tests require --variant non-fips (they rely on curl SigV4 + non-FIPS build flags)." >&2
  exit 1
fi

# Build binaries once to avoid repeated compilation in the provisioning steps.
# shellcheck disable=SC2086
cargo build -p cosmian_kms_server $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --bin cosmian_kms

KMS_BIN="${REPO_ROOT}/target/${BUILD_PROFILE}/cosmian_kms"

rm -f "${LOG_PATH}"

# Use a per-run temp sqlite directory so repeated runs are stable.
SQLITE_PATH="$(mktemp -d -t kms-xks-sqlite-XXXXXX)"

# Compose a minimal config based on test_data/aws_xks/aws_xks.toml and add a DB section.
# This keeps the documented XKS config intact while making the test hermetic.
KMS_CONF_PATH="$(mktemp -t kms-xks-conf-XXXXXX.toml)"
cat "${REPO_ROOT}/test_data/aws_xks/aws_xks.toml" >"${KMS_CONF_PATH}"
cat >>"${KMS_CONF_PATH}" <<EOF

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true
EOF

echo "Starting KMS server (background) using ${KMS_CONF_PATH} ..."
RUST_LOG="info,cosmian_kms=debug" \
  "${KMS_BIN}" -c "${KMS_CONF_PATH}" \
  >"${LOG_PATH}" 2>&1 &
KMS_PID=$!

wait_for_kms_listen

echo "Provisioning XKS test keys and access grants..."
cd "${REPO_ROOT}/test_data/aws_xks/scripts"

# Shell helpers from the vendored test client.
# - utils/config.sh provides URI prefix + SigV4 credentials and key IDs
# - utils/test_config.sh provides default REGION/SCHEME values
source ./utils/config.sh
source ./utils/test_config.sh

# Keep the same principal ARN as the vendored curl-suite.
aws_principal_arn="arn:aws:iam::123456789012:user/Alice"

xks_create_key() {
  local key_id="$1"
  local request_id
  request_id="$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' || date +%s)"

  local json_body
  json_body="$(
    cat <<EOF
{
  "requestMetadata": {
    "awsPrincipalArn": "${aws_principal_arn}",
    "kmsOperation": "CreateKey",
    "kmsRequestId": "${request_id}"
  }
}
EOF
  )"

  # The XKS endpoint is authenticated with SigV4.
  local url="${SCHEME}${XKS_PROXY_HOST}/${URI_PREFIX}/kms/xks/v1/keys/${key_id}/metadata"
  local response
  response="$(
    # shellcheck disable=SC2086 # SECURE may intentionally contain multiple curl args (e.g., --cacert <path>)
    curl -k -sS ${SECURE:-} \
      -H "Content-Type:application/json" \
      --aws-sigv4 "aws:amz:${REGION}:kms-xks-proxy" \
      --user "${SIGV4_ACCESS_KEY_ID}:${SIGV4_SECRET_ACCESS_KEY}" \
      --data-binary "${json_body}" \
      "${url}"
  )"

  if ! grep -q '"keyStatus"' <<<"${response}"; then
    echo "Failed to CreateKey for ${key_id}. Response:" >&2
    echo "${response}" >&2
    return 1
  fi
}

revoke_op_for_alice() {
  local key_id="$1"
  local op="$2"

  # Access endpoints are admin-authenticated (default user) in this test config.
  local response
  response="$(
    curl -k -sS \
      -H "Content-Type:application/json" \
      -X POST "${KMS_URL}/access/revoke" \
      --data-binary "$(
        cat <<EOF
{
  "unique_identifier": "${key_id}",
  "user_id": "${aws_principal_arn}",
  "operation_types": ["${op}"]
}
EOF
      )"
  )"

  if ! grep -q '"success"' <<<"${response}"; then
    echo "Failed to revoke ${op} for ${aws_principal_arn} on ${key_id}. Response:" >&2
    echo "${response}" >&2
    return 1
  fi
}

# Ensure the upstream curl-suite keys exist before running any DescribeKey/Encrypt calls.
xks_create_key "aws_xks_kek"
xks_create_key "encrypt_only_key"
xks_create_key "decrypt_only_key"

# Enforce the expected usage restrictions.
revoke_op_for_alice "encrypt_only_key" "decrypt"
revoke_op_for_alice "decrypt_only_key" "encrypt"

echo "Running vendored AWS XKS curl-based test client..."

# Ensure the client runs with bash 4.2+ (macOS system bash is 3.2).
BASH="$(command -v bash)"
export BASH

./test_all

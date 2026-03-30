#!/usr/bin/env bash
# Azure EKM HTTP Smoke Test
# Builds the KMS, imports an AES-256 and an RSA-2048 key pair via the KMIP REST API,
# then validates the EKM /info, /metadata, /wrapkey and /unwrapkey endpoints.
#
# No TLS or mTLS is required: the server runs in plain HTTP mode with authentication
# disabled (--azure-ekm-disable-auth).  For a TLS + mTLS variant, see run_azure_ekm_mtls_test.sh.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

# Configuration
KMS_PORT=6790
EKM_PREFIX="cosmian0"
KMS_URL="http://localhost:${KMS_PORT}"

export KMS_HTTP_HOST="localhost"
export KMS_HTTP_PORT="${KMS_PORT}"

AES_KEY_ID="aes256"

REQCTX='{"request_id":"test-001","correlation_id":"test-corr-001","pool_name":"test-pool"}'

KMS_PID=""

cleanup() {
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; wait "${KMS_PID}" 2>/dev/null || true; }
    [ -n "${SQLITE_PATH:-}" ] && { rm -rf "${SQLITE_PATH}" || true; }
    [ -n "${KMS_CONF_PATH:-}" ] && { rm -f "${KMS_CONF_PATH}" || true; }
}
trap cleanup EXIT

# KMIP helper functions
kmip_post() {
  local payload="$1"
  # Don't use -f: we want the response body even on HTTP 4xx.
  curl -sS -X POST "http://${KMS_HTTP_HOST}:${KMS_HTTP_PORT}/kmip/2_1" \
    -H "Content-Type: application/json" \
    -d "${payload}"
}

activate_key() {
  local uid="$1"
  # Minimal KMIP JSON-TTLV Activate request.
  kmip_post "{\"tag\":\"Activate\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${uid}\"}]}"
}

# The server expects `sqlite_path` to be a directory where it creates `kms.db`.
SQLITE_PATH="$(mktemp -d -t kms-ekm-XXXXXX)"

# Write a minimal server config so we can control HTTP bind + sqlite path.
KMS_CONF_PATH="$(mktemp -t kms-ekm-conf-XXXXXX.toml)"
cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "${KMS_HTTP_HOST}"
port = ${KMS_HTTP_PORT}

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true

[azure_ekm_config]
azure_ekm_enable = true
azure_ekm_disable_client_auth = true
azure_ekm_path_prefix = "${EKM_PREFIX}"
EOF

# shellcheck disable=SC2068
cargo build ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

# shellcheck disable=SC2068
cargo run ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms -- \
    --config "${KMS_CONF_PATH}" \
    &
KMS_PID=$!

if ! _wait_for_port localhost "${KMS_PORT}" 60; then
    echo "ERROR: KMS server failed to start or bind to port ${KMS_PORT}"
    exit 1
fi

# 2. Create an AES-256 key
# Using a fresh temporary SQLite database.

# Redefine create_aes_key to include CryptographicUsageMask (12 = Encrypt | Decrypt)
# This function is ALMOST the same one as `test_otel_export.sh`, consider refactoring if it's needed elsewhere
create_aes_key() {
  local uid="$1"
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
            "tag": "CryptographicUsageMask",
            "type": "Integer",
            "value": 12
          },
          {
            "tag": "KeyFormatType",
            "type": "Enumeration",
            "value": "TransparentSymmetricKey"
          },
          {
            "tag": "UniqueIdentifier",
            "type": "TextString",
            "value": "'"${uid}"'"
          }
        ]
      }
    ]
  }'
}

create_aes_key "${AES_KEY_ID}" > /dev/null
activate_key "${AES_KEY_ID}" > /dev/null

# 3. EKM /info endpoint
curl -sSf -X POST "${KMS_URL}/azureekm/${EKM_PREFIX}/info?api-version=0.1-preview" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}}" > /dev/null

# 4. EKM /metadata — AES key
curl -sSf -X POST "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/metadata?api-version=0.1-preview" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}}" > /dev/null

# 5. Sad path: /metadata for a non-existent key must return 404
echo "==> EKM: Sad path /metadata (non-existent key)"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${KMS_URL}/azureekm/${EKM_PREFIX}/does-not-exist/metadata?api-version=0.1-preview" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}}")

if [ "${HTTP_STATUS}" != "404" ]; then
    echo "ERROR: Expected HTTP 404 for non-existent key, but got ${HTTP_STATUS}"
    exit 1
fi
echo "==> Sad path successfully returned 404"

# 6. EKM Round trip: /wrapkey and /unwrapkey
echo "==> EKM: Running round-trip wrap/unwrap test..."
PLAINTEXT="This is a secret message"
# Base64URL encoding (no padding, replaces + /)
PLAINTEXT_B64=$(echo -n "${PLAINTEXT}" | base64 | tr -d '=' | tr '/+' '_-')

# Wrap
WRAP_RESPONSE=$(curl -sSf -X POST "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/wrapkey?api-version=0.1-preview" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}, \"alg\":\"A256KW\", \"value\":\"${PLAINTEXT_B64}\"}")
WRAPPED_B64=$(echo "${WRAP_RESPONSE}" | sed -E 's/.*"value":"([^"]+)".*/\1/')

# Unwrap
UNWRAP_RESPONSE=$(curl -sSf -X POST "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/unwrapkey?api-version=0.1-preview" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}, \"alg\":\"A256KW\", \"value\":\"${WRAPPED_B64}\"}")
UNWRAPPED_B64=$(echo "${UNWRAP_RESPONSE}" | sed -E 's/.*"value":"([^"]+)".*/\1/')

# Verify
if [ "${PLAINTEXT_B64}" != "${UNWRAPPED_B64}" ]; then
    echo "ERROR: Round trip wrap/unwrap failed!"
    echo "Expected: ${PLAINTEXT_B64}"
    echo "Got:      ${UNWRAPPED_B64}"
    exit 1
fi
echo "==> Round trip wrap/unwrap OK."

echo "Azure EKM test PASSED"

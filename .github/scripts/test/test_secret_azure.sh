#!/usr/bin/env bash
set -euo pipefail
set -x

# Secret backend integration test — Azure Key Vault
#
# Creates a secret in an existing Azure Key Vault, runs the Rust #[ignore]
# integration test, then deletes the secret (soft-delete; purge protection
# may prevent immediate purge).
#
# Required env vars (from GitHub secrets):
#   AZURE_TENANT_ID      — Azure AD tenant ID
#   AZURE_CLIENT_ID      — service-principal application (client) ID
#   AZURE_CLIENT_SECRET  — service-principal secret
#   AZURE_KV_NAME        — Key Vault name (e.g. keyvault-workload-v3)
#   AZURE_KV_SP_OBJECT_ID — Object ID of the service principal in Enterprise
#                           Applications (for role assignment)
#
# Feature flag: secret-azure

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required."
require_cmd curl "curl is required for Azure REST API calls."
require_cmd python3 "python3 is required for JSON parsing."

echo "========================================="
echo "Running secret backend test: Azure Key Vault"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

: "${AZURE_TENANT_ID:?AZURE_TENANT_ID must be set}"
: "${AZURE_CLIENT_ID:?AZURE_CLIENT_ID must be set}"
: "${AZURE_CLIENT_SECRET:?AZURE_CLIENT_SECRET must be set}"
: "${AZURE_KV_NAME:?AZURE_KV_NAME must be set}"

SECRET_NAME="kms-ci-secret-backend-test"
SECRET_VALUE="ci-secret-value"
KV_BASE_URL="https://${AZURE_KV_NAME}.vault.azure.net"

# ── OAuth2 helper ─────────────────────────────────────────────────────────────
get_kv_token() {
  curl -sf -X POST \
    "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=${AZURE_CLIENT_ID}" \
    -d "client_secret=${AZURE_CLIENT_SECRET}" \
    -d "scope=https://vault.azure.net/.default" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

cleanup() {
  echo "Deleting Azure KV secret ${SECRET_NAME}..."
  local token
  token=$(get_kv_token) || true
  if [ -n "${token:-}" ]; then
    curl -sf -X DELETE \
      "${KV_BASE_URL}/secrets/${SECRET_NAME}?api-version=7.4" \
      -H "Authorization: Bearer ${token}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "Obtaining Azure AD access token..."
KV_TOKEN=$(get_kv_token)

# Recover the secret if it is in soft-deleted state (e.g. left over from a previous run
# on a vault with purge protection enabled). A 404 here is normal and ignored.
echo "Recovering soft-deleted secret ${SECRET_NAME} if present..."
RECOVER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${KV_BASE_URL}/deletedsecrets/${SECRET_NAME}/recover?api-version=7.4" \
  -H "Authorization: Bearer ${KV_TOKEN}" \
  -H "Content-Type: application/json" || true)
echo "Recover response: HTTP ${RECOVER_STATUS}"

# If recovery was triggered (202), poll until the secret is available or timeout
if [ "${RECOVER_STATUS}" = "202" ]; then
  echo "Waiting for recovery to complete..."
  for i in $(seq 1 30); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "${KV_BASE_URL}/secrets/${SECRET_NAME}?api-version=7.4" \
      -H "Authorization: Bearer ${KV_TOKEN}" || true)
    if [ "${STATUS}" = "200" ]; then
      echo "Secret recovered and accessible (attempt ${i})"
      break
    fi
    if [ "${i}" -eq 30 ]; then
      echo "WARNING: Secret not accessible after recovery, attempting PUT anyway"
    fi
    sleep 2
  done
fi

echo "Creating secret ${SECRET_NAME} in vault ${AZURE_KV_NAME}..."
PUT_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
  "${KV_BASE_URL}/secrets/${SECRET_NAME}?api-version=7.4" \
  -H "Authorization: Bearer ${KV_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"value\":\"${SECRET_VALUE}\"}")
PUT_STATUS=$(echo "${PUT_RESPONSE}" | tail -1)
PUT_BODY=$(echo "${PUT_RESPONSE}" | head -n -1)
if [ "${PUT_STATUS}" -lt 200 ] || [ "${PUT_STATUS}" -ge 300 ]; then
  echo "ERROR: PUT secret failed (HTTP ${PUT_STATUS}): ${PUT_BODY}" >&2
  exit 1
fi
echo "Secret created (HTTP ${PUT_STATUS})"
PUT_STATUS=$(echo "${PUT_RESPONSE}" | tail -1)
PUT_BODY=$(echo "${PUT_RESPONSE}" | head -n -1)
if [ "${PUT_STATUS}" -lt 200 ] || [ "${PUT_STATUS}" -ge 300 ]; then
  echo "ERROR: PUT secret failed (HTTP ${PUT_STATUS}): ${PUT_BODY}" >&2
  exit 1
fi
echo "Secret created (HTTP ${PUT_STATUS})"

echo "Building cosmian_kms_server with secret-azure feature..."
cargo build -p cosmian_kms_server --features secret-azure

echo "Running Azure KV integration test..."
AZURE_TENANT_ID="${AZURE_TENANT_ID}" \
AZURE_CLIENT_ID="${AZURE_CLIENT_ID}" \
AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET}" \
KMS_TEST_AZURE_KV_URI="azure-kv://${AZURE_KV_NAME}/secrets/${SECRET_NAME}" \
KMS_TEST_AZURE_KV_EXPECTED="${SECRET_VALUE}" \
cargo test -p cosmian_kms_server --features secret-azure --lib -- \
  --ignored --nocapture test_secret_azure_kv

echo "Azure Key Vault secret backend test completed successfully."

#!/usr/bin/env bash
set -euo pipefail
set -x

# Secret backend integration test — HashiCorp Vault KV-v2
#
# Starts a dev-mode Vault container, creates a test secret, runs the Rust
# #[ignore] integration test, then cleans up.
#
# Required tools: docker, cargo
# Feature flag:   secret-vault

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required."
require_cmd docker "Docker is required to run the Vault container."
require_cmd curl "curl is required for Vault readiness checks."

echo "========================================="
echo "Running secret backend test: HashiCorp Vault"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

VAULT_CONTAINER="kms-ci-vault-$$"
VAULT_PORT=18200
VAULT_ADDR="http://127.0.0.1:${VAULT_PORT}"
VAULT_TOKEN="ci-root-token"

# Test secret parameters
VAULT_MOUNT="secret"
VAULT_PATH="kms-ci/db"
VAULT_FIELD="password"
SECRET_VALUE="ci-secret-value"

cleanup() {
  echo "Stopping Vault container..."
  docker rm -f "${VAULT_CONTAINER}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting Vault dev container on port ${VAULT_PORT}..."
docker run -d \
  --name "${VAULT_CONTAINER}" \
  -p "${VAULT_PORT}:8200" \
  -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" \
  -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  hashicorp/vault:1.17 \
  vault server -dev

echo "Waiting for Vault to be ready..."
for i in $(seq 1 60); do
  # Accept any HTTP response (200=active, 429=standby, 501=not init, 503=sealed)
  # curl without -f so it doesn't fail on non-2xx; we just need the server to respond.
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${VAULT_ADDR}/v1/sys/health" 2>/dev/null || true)
  if [ "${STATUS}" = "200" ] || [ "${STATUS}" = "429" ]; then
    echo "Vault is ready (attempt ${i}, status ${STATUS})"
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: Vault did not become ready in time (last status: ${STATUS})" >&2
    echo "--- Vault container logs ---" >&2
    docker logs "${VAULT_CONTAINER}" >&2 || true
    exit 1
  fi
  sleep 2
done

echo "Enabling KV-v2 secrets engine at mount '${VAULT_MOUNT}'..."
curl -sf -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d '{"type":"kv","options":{"version":"2"}}' \
  "${VAULT_ADDR}/v1/sys/mounts/${VAULT_MOUNT}" || true  # may already exist in dev mode

echo "Writing test secret ${VAULT_MOUNT}/${VAULT_PATH}#${VAULT_FIELD}..."
curl -sf -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"data\":{\"${VAULT_FIELD}\":\"${SECRET_VALUE}\"}}" \
  "${VAULT_ADDR}/v1/${VAULT_MOUNT}/data/${VAULT_PATH}"

echo "Building cosmian_kms_server with secret-vault feature..."
cargo build -p cosmian_kms_server --features secret-vault

echo "Running Vault integration test..."
VAULT_ADDR="${VAULT_ADDR}" \
VAULT_TOKEN="${VAULT_TOKEN}" \
KMS_TEST_VAULT_URI="vault://${VAULT_MOUNT}/${VAULT_PATH}#${VAULT_FIELD}" \
KMS_TEST_VAULT_EXPECTED="${SECRET_VALUE}" \
cargo test -p cosmian_kms_server --features secret-vault --lib -- \
  --ignored --nocapture test_secret_vault

echo "Vault secret backend test completed successfully."

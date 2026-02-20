#!/usr/bin/env bash
# Azure EKM mTLS E2E Test: tests that the KMS (with EKM enabled) works only with mTLS.
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DATA_DIR="${SCRIPT_DIR}/azure_ekm_test_data"

source "$SCRIPT_DIR/common.sh"
init_build_env "$@"
setup_test_logging

# Certificates
CLIENT_CERT="${DATA_DIR}/client_cert.pem"
CLIENT_KEY="${DATA_DIR}/client_key.pem"
SERVER_CA="${DATA_DIR}/server_ca_cert.pem"

# Verify test data exists; generate it if not
if [ ! -f "${CLIENT_CERT}" ]; then
    echo "Test data not found — running generator..."
    bash "${DATA_DIR}/generate_azure_ekm_test_data.sh"
fi

# EKM endpoint
KMS_PORT=6789
EKM_PREFIX="cosmian0"
EKM_INFO_URL="https://localhost:${KMS_PORT}/azureekm/${EKM_PREFIX}/info?api-version=0.1-preview"

cleanup() {
    echo "Stopping KMS server..."
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" || true; wait "${KMS_PID}" || true; }
}
trap cleanup EXIT

echo "Building KMS server binary (${VARIANT_NAME})..."
cargo build ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

echo "Starting KMS server on port ${KMS_PORT} with mTLS config..."
export KMS_HOSTNAME="127.0.0.1"
export KMS_PORT="${KMS_PORT}"
export KMS_TLS_P12_FILE="${DATA_DIR}/server.p12"
export KMS_TLS_P12_PASSWORD="password"
export KMS_TLS_CERT_FILE="${DATA_DIR}/server_cert.pem"
export KMS_TLS_KEY_FILE="${DATA_DIR}/server_key.pem"
export KMS_CLIENTS_CA_CERT_FILE="${DATA_DIR}/client_ca_cert.pem"
export KMS_AZURE_EKM_ENABLE="true"
export KMS_AZURE_EKM_PATH_PREFIX="${EKM_PREFIX}"
export KMS_AZURE_EKM_PROXY_VENDOR="Cosmian"
export KMS_AZURE_EKM_PROXY_NAME="EKM Proxy Service"
export KMS_AZURE_EKM_VENDOR="Cosmian"
export KMS_AZURE_EKM_PRODUCT="Cosmian KMS"
export KMS_AZURE_EKM_DISABLE_CLIENT_AUTH="false"

cargo run ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms &
KMS_PID=$!

echo "Waiting for KMS port ${KMS_PORT} to be open (up to 30s)..."
_wait_for_port localhost "${KMS_PORT}" 30
echo "KMS server is ready!"

# Sad path: no client certificate -> server must reject
echo ""
echo "Sad path: calling /info WITHOUT a client certificate (expect auth rejection)..."
SAD_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${EKM_INFO_URL}" \
    --cacert "${SERVER_CA}" \
    -H "Content-Type: application/json" \
    -d '{"request_context":{"request_id":"sad","correlation_id":"sad","pool_name":"sad"}}' \
    2>&1 || true)
echo "HTTP status (sad path): ${SAD_CODE}"
case "${SAD_CODE}" in
    2*) echo "ERROR: server returned HTTP ${SAD_CODE} without a client certificate — auth is not enforced!"; exit 1 ;;
    *)  echo "Sad path OK: server correctly rejected the unauthenticated request (HTTP ${SAD_CODE})." ;;
esac

# Happy path: valid mTLS
echo "Happy path: calling /info with valid client certificate..."
RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${EKM_INFO_URL}" \
    --cacert "${SERVER_CA}" \
    --cert   "${CLIENT_CERT}" \
    --key    "${CLIENT_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "request_context": {
            "request_id": "test-request-123",
            "correlation_id": "test-correlation-456",
            "pool_name": "test-pool"
        }
    }')
HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | head -n-1)
echo "Response body: ${BODY}"
echo "HTTP status:   ${HTTP_CODE}"
[ "${HTTP_CODE}" = "200" ] || { echo "ERROR: expected HTTP 200, got ${HTTP_CODE}"; exit 1; }

echo -e "\n\nmTLS verification successful!"

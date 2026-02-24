#!/usr/bin/env bash
# Azure EKM mTLS E2E Test: tests that the KMS (with EKM enabled) works only with mTLS.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
DATA_DIR="${REPO_ROOT}/test_data/certificates/azure_ekm_test_data"

source "$SCRIPT_DIR/common.sh"
init_build_env "$@"
setup_test_logging

# Certificates
CLIENT_CERT="${DATA_DIR}/client_cert.pem"
CLIENT_KEY="${DATA_DIR}/client_key.pem"
SERVER_CA="${DATA_DIR}/server_ca_cert.pem"

# EKM endpoint
KMS_PORT=6789
EKM_PREFIX="cosmian0"
EKM_INFO_URL="https://localhost:${KMS_PORT}/azureekm/${EKM_PREFIX}/info?api-version=0.1-preview"

cleanup() {
    echo "Stopping KMS server..."
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" || true; wait "${KMS_PID}" || true; }
    [ -n "${SQLITE_PATH:-}" ] && rm -rf "${SQLITE_PATH}" || true
    [ -n "${KMS_CONF_PATH:-}" ] && rm -f "${KMS_CONF_PATH}" || true
}
trap cleanup EXIT

echo "Building KMS server binary (${VARIANT_NAME})..."
cargo build ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

echo "Starting KMS server on port ${KMS_PORT} with mTLS config..."

# The server expects `sqlite_path` to be a directory where it creates `kms.db`.
SQLITE_PATH="$(mktemp -d -t kms-ekm-mtls-XXXXXX)"

# Write a minimal server config so we can control HTTP bind + sqlite path.
KMS_CONF_PATH="$(mktemp -t kms-ekm-mtls-conf-XXXXXX.toml)"
cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "127.0.0.1"
port = ${KMS_PORT}

[tls]
tls_p12_file = "${DATA_DIR}/server.p12"
tls_p12_password = "password"
clients_ca_cert_file = "${DATA_DIR}/client_ca_cert.pem"

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true

[azure_ekm_config]
azure_ekm_enable = true
azure_ekm_path_prefix = "${EKM_PREFIX}"
azure_ekm_proxy_vendor = "Cosmian"
azure_ekm_proxy_name = "EKM Proxy Service"
azure_ekm_ekm_vendor = "Cosmian"
azure_ekm_ekm_product = "Cosmian KMS"
azure_ekm_disable_client_auth = false
EOF

cargo run ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms -- \
    --config "${KMS_CONF_PATH}" \
    &
KMS_PID=$!

echo "Waiting for KMS port ${KMS_PORT} to be open (up to 30s)..."
if ! _wait_for_port localhost "${KMS_PORT}" 30; then
    echo "ERROR: KMS server failed to start or bind to port ${KMS_PORT}"
    exit 1
fi
echo "KMS server is ready!"

# ---------------------------------------------------------------------------
# Sad path: no client certificate -> server must reject with 401
# ---------------------------------------------------------------------------
echo "==> Sad path: calling /info WITHOUT a client certificate"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${EKM_INFO_URL}" \
    --cacert "${SERVER_CA}" \
    -H "Content-Type: application/json" \
    -d '{"request_context":{"request_id":"sad","correlation_id":"sad","pool_name":"sad"}}')

if [ "${HTTP_STATUS}" != "401" ]; then
    echo "ERROR: Expected HTTP 401 for missing client cert, but got ${HTTP_STATUS}"
    exit 1
fi
echo "==> Sad path successfully returned 401"

# ---------------------------------------------------------------------------
# Happy path: valid mTLS -> server must accept with 200
# ---------------------------------------------------------------------------
echo "==> Happy path: calling /info with valid client certificate"
curl -sSf -X POST "${EKM_INFO_URL}" \
    --cacert "${SERVER_CA}" \
    --cert   "${CLIENT_CERT}" \
    --key    "${CLIENT_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"request_context":{"request_id":"test","correlation_id":"test","pool_name":"test"}}' > /dev/null

echo "==> Happy path successfully returned 200"

echo "Azure EKM mTLS test PASSED"
exit 0

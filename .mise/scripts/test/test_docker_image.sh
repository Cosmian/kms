#!/bin/bash

set -exuo pipefail

# Prefer cargo-installed binaries if present.
export PATH="$HOME/.cargo/bin:$PATH"

# Port isolation: source test_slots.sh to compute slot-aware ports.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.mise/lib/test_slots.sh
source "${SCRIPT_DIR}/../../lib/test_slots.sh"

# Single compose file containing all test stacks.
# Path is relative to the repo root (the script's working directory).
COMPOSE_FILE=".mise/scripts/docker-compose.yml"
export COMPOSE_FILE

# KMS_TLS_CONFIG_FLAVOR must be set by the caller (mise task: test:docker).
# Accepted values: fips, non_fips
: "${KMS_TLS_CONFIG_FLAVOR:?KMS_TLS_CONFIG_FLAVOR must be set by the caller (mise task: test:docker)}"
echo "Using KMS_TLS_CONFIG_FLAVOR=${KMS_TLS_CONFIG_FLAVOR}"

# Config paths
CONFIG=~/.cosmian/cosmian-no-tls.toml
TLS_CONFIG=~/.cosmian/cosmian-tls.toml

# Host ports (slot-aware via test_slots.sh).
HOST_HTTP_PORT="${KMS_SLOT_HTTP_PORT}"
HOST_TLS_PORT="${KMS_SLOT_TLS_PORT}"
HOST_TLS13_PORT="${KMS_SLOT_TLS13_PORT}"
HOST_SOCKET_TLS_PORT="${KMS_SLOT_KMIP_PORT}"
HOST_SOCKET_TLS13_PORT="${KMS_SLOT_KMIP_TLS13_PORT}"

# Cert paths
CA_CERT="test_data/certificates/client_server/ca/ca.crt"
CLIENT_CERT="test_data/certificates/client_server/owner/owner.client.acme.com.crt"
CLIENT_KEY="test_data/certificates/client_server/owner/owner.client.acme.com.key"
CLIENT_PKCS12_PATH="test_data/certificates/client_server/owner/owner.client.acme.com.p12"

KMS_URL_HTTP="http://127.0.0.1:${HOST_HTTP_PORT}"
KMS_URL_HTTPS="https://127.0.0.1:${HOST_TLS_PORT}"

# Write CLI config files
mkdir -p ~/.cosmian

# shellcheck disable=SC2086
echo '
print_json = false

[http_config]
server_url = "'$KMS_URL_HTTP'"
' | tee "$CONFIG"

# shellcheck disable=SC2086
echo '
print_json = false

[http_config]
server_url = "'$KMS_URL_HTTPS'"
accept_invalid_certs = true
tls_client_pkcs12_path = "'$CLIENT_PKCS12_PATH'"
tls_client_pkcs12_password = "password"
' | tee "$TLS_CONFIG"

# Use cargo run to execute ckms from the workspace instead of installing
if command -v cargo >/dev/null 2>&1; then
  COSMIAN_BIN="cargo run -p ckms --"
  echo "Using cargo run to execute ckms from workspace"
else
  COSMIAN_BIN=""
  echo "Warning: cargo not available; skipping CLI-dependent tests."
fi

if [[ -z "$COSMIAN_BIN" ]]; then
  echo "Warning: KMS CLI not available; skipping CLI-dependent tests."
else
  $COSMIAN_BIN --version
fi

# Start all stacks; --wait blocks until every service with a healthcheck is healthy.
docker compose -f "$COMPOSE_FILE" up -d --wait --remove-orphans

echo "All KMS services are healthy:"
docker compose -f "$COMPOSE_FILE" ps

# Verify servers are responding
echo "Using compose file: $COMPOSE_FILE"
echo "Docker image name: ${DOCKER_IMAGE_NAME:-not set}"

# Function to test OpenSSL connections
openssl_test() {
  local host_port=$1
  local tls_version=$2
  echo "Testing $host_port with TLS $tls_version"
  echo "QUIT" | openssl s_client -"$tls_version" -connect "$host_port" \
    -CAfile "$CA_CERT" \
    -cert "$CLIENT_CERT" \
    -key "$CLIENT_KEY" \
    -verify_return_error \
    -brief
}

# Function to test expected TLS failures
test_tls_failure() {
  local host_port=$1
  local tls_version=$2
  local description=$3

  if openssl_test "$host_port" "$tls_version"; then
    echo "ERROR: $description - TLS $tls_version test should have failed on $host_port"
    exit 1
  else
    echo "EXPECTED: $description - TLS $tls_version correctly rejected on $host_port"
  fi
}

# Create symmetric keys
if [[ -n "$COSMIAN_BIN" ]]; then
  $COSMIAN_BIN -c "$CONFIG" sym keys create
  $COSMIAN_BIN -c "$TLS_CONFIG" sym keys create
else
  echo "Skipping key creation: KMS CLI not available"
fi

# Test TLS on HTTP server with default options
openssl_test "127.0.0.1:${HOST_TLS_PORT}" "tls1_2"
openssl_test "127.0.0.1:${HOST_TLS_PORT}" "tls1_3"

# Test TLS socket server with default options
openssl_test "127.0.0.1:${HOST_SOCKET_TLS_PORT}" "tls1_2"
openssl_test "127.0.0.1:${HOST_SOCKET_TLS_PORT}" "tls1_3"

# Test TLS on HTTP server with specific TLS1.3
test_tls_failure "127.0.0.1:${HOST_TLS13_PORT}" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port ${HOST_TLS13_PORT}"
openssl_test "127.0.0.1:${HOST_TLS13_PORT}" "tls1_3"

# Test TLS socket server with specific TLS1.3
test_tls_failure "127.0.0.1:${HOST_SOCKET_TLS13_PORT}" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port ${HOST_SOCKET_TLS13_PORT}"
openssl_test "127.0.0.1:${HOST_SOCKET_TLS13_PORT}" "tls1_3"

# Test UI endpoints
curl -I "http://127.0.0.1:${HOST_HTTP_PORT}/ui/index.html"
curl --insecure -I "https://127.0.0.1:${HOST_TLS_PORT}/ui/index.html"
curl --insecure -I "https://127.0.0.1:${HOST_TLS13_PORT}/ui/index.html"

# === No-config smoke test ===
# Verify the KMS image works out of the box with no conf file, no env vars.
# Also tests that the UI is served from the default endpoint.
HOST_NO_CONF_PORT="${KMS_SLOT_KMS_NO_CONF_PORT:-13098}"
KMS_NO_CONF_URL="http://127.0.0.1:${HOST_NO_CONF_PORT}"
echo "=== No-config smoke test: ${KMS_NO_CONF_URL} ==="

version_response=$(curl -sf "${KMS_NO_CONF_URL}/version")
echo "  /version → ${version_response}"
echo "${version_response}" | grep -q '"' || {
  echo "ERROR: /version did not return expected JSON"
  exit 1
}

# UI must be served at /ui/index.html
curl -sf "${KMS_NO_CONF_URL}/ui/index.html" >/dev/null || {
  echo "ERROR: UI not served at ${KMS_NO_CONF_URL}/ui/index.html"
  exit 1
}
echo "  UI served at /ui/index.html ✓"

echo "=== No-config smoke test passed ==="

# === Config-file based compose test ===
echo "Running config-based compose test ($COMPOSE_FILE:kms-with-conf)"
docker compose -f "$COMPOSE_FILE" logs --tail=120 kms-with-conf || true

# === Example docker-compose smoke test ===
echo "Running example compose test ($COMPOSE_FILE:kms-example)"
docker compose -f "$COMPOSE_FILE" logs --tail=120 kms-example || true

# === Load balancer shutdown behavior test ===
echo "Running load balancer shutdown test (.mise/scripts/test/test_lb_kms_shutdown.sh)"
bash .mise/scripts/test/test_lb_kms_shutdown.sh

# === Oracle TDE HSM test ===
# Run Oracle Database + KMS side by side and verify that Oracle can use
# the Cosmian PKCS#11 library (bundled in the KMS image) as a TDE HSM.
echo "Running Oracle TDE HSM test (.mise/scripts/oracle/)"

# Start Oracle Database and KMS using the built image
docker compose -f "$COMPOSE_FILE" --profile oracle down --remove-orphans || true

# Wipe the KMS data directory so kms-oracle starts with a clean SQLite database.
# The directory is persisted on the host between runs (it is not inside the container),
# so stale keys from a previous run would cause ORA-00600 (key exists in KMS but
# Oracle no longer knows about it).
rm -rf .mise/scripts/oracle/cosmian-kms
mkdir -p .mise/scripts/oracle/cosmian-kms

docker compose -f "$COMPOSE_FILE" --profile oracle up -d --wait

# Copy the Cosmian PKCS#11 library from the KMS image into Oracle
bash .mise/scripts/oracle/set_hsm.sh

docker compose -f "$COMPOSE_FILE" --profile oracle down --remove-orphans || true
echo "Oracle TDE HSM test completed successfully"
# Oracle TDE remote upgrade and smoke test is a separate step: mise run test:docker-oracle
# It runs only on non-fips amd64, gated by the CI workflow condition.

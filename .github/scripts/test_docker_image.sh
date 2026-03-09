#!/bin/bash

set -exuo pipefail

# Prefer cargo-installed binaries if present.
export PATH="$HOME/.cargo/bin:$PATH"

# Single compose file containing all test stacks.
COMPOSE_FILE=".github/scripts/docker-compose.yml"

# Detect FIPS vs non-FIPS from image name robustly
# FIPS images: ghcr.io/cosmian/kms-fips or cosmian-kms:* -fips (not -non-fips)
# Non-FIPS images: ghcr.io/cosmian/kms or cosmian-kms:* -non-fips
if [[ "${DOCKER_IMAGE_NAME:-}" == *"-non-fips"* ]]; then
    export KMS_TLS_CONFIG_FLAVOR="non_fips"
    echo "Detected non-FIPS image: ${DOCKER_IMAGE_NAME}"
elif [[ "${DOCKER_IMAGE_NAME:-}" == *"-fips"* ]] || [[ "${DOCKER_IMAGE_NAME:-}" == *"kms-fips"* ]]; then
    export KMS_TLS_CONFIG_FLAVOR="fips"
    echo "Detected FIPS image: ${DOCKER_IMAGE_NAME}"
else
    # Default to non-FIPS if ambiguous
    export KMS_TLS_CONFIG_FLAVOR="non_fips"
    echo "Image variant ambiguous; defaulting to non-FIPS: ${DOCKER_IMAGE_NAME}"
fi

# Config paths
CONFIG=~/.cosmian/cosmian-no-tls.toml
TLS_CONFIG=~/.cosmian/cosmian-tls.toml

# Fixed host ports (compose publishes deterministic ports).
HOST_HTTP_PORT=9998
HOST_TLS_PORT=9999
HOST_TLS13_PORT=10000
HOST_SOCKET_TLS_PORT=5696
HOST_SOCKET_TLS13_PORT=5697

# Cert paths
CA_CERT="test_data/certificates/client_server/ca/ca.crt"
CLIENT_CERT="test_data/certificates/client_server/owner/owner.client.acme.com.crt"
CLIENT_KEY="test_data/certificates/client_server/owner/owner.client.acme.com.key"
CLIENT_PKCS12_PATH="test_data/certificates/client_server/owner/owner.client.acme.com.p12"

KMS_URL_HTTP="http://127.0.0.1:${HOST_HTTP_PORT}"
KMS_URL_HTTPS="https://127.0.0.1:${HOST_TLS_PORT}"

# Write CLI config files
mkdir -p ~/.cosmian

echo '
print_json = false

[http_config]
server_url = "'$KMS_URL_HTTP'"
' | tee "$CONFIG"

echo '
print_json = false

[http_config]
server_url = "'$KMS_URL_HTTPS'"
accept_invalid_certs = true
ssl_client_pkcs12_path = "'$CLIENT_PKCS12_PATH'"
ssl_client_pkcs12_password = "password"
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

# === Config-file based compose test ===
echo "Running config-based compose test ($COMPOSE_FILE:kms-with-conf)"
docker compose -f "$COMPOSE_FILE" logs --tail=120 kms-with-conf || true

# === Example docker-compose smoke test ===
echo "Running example compose test ($COMPOSE_FILE:kms-example)"
docker compose -f "$COMPOSE_FILE" logs --tail=120 kms-example || true

# === Load balancer shutdown behavior test ===
echo "Running load balancer shutdown test (.github/scripts/test_lb_kms_shutdown.sh)"
bash .github/scripts/test_lb_kms_shutdown.sh

# === Oracle TDE HSM test ===
# Run Oracle Database + KMS side by side and verify that Oracle can use
# the Cosmian PKCS#11 library (bundled in the KMS image) as a TDE HSM.
echo "Running Oracle TDE HSM test (.github/scripts/oracle/)"

# Start Oracle Database and KMS using the built image
docker compose -f "$COMPOSE_FILE" --profile oracle down --remove-orphans || true

# Wipe the KMS data directory so kms-oracle starts with a clean SQLite database.
# The directory is persisted on the host between runs (it is not inside the container),
# so stale keys from a previous run would cause ORA-00600 (key exists in KMS but
# Oracle no longer knows about it).
rm -rf .github/scripts/oracle/cosmian-kms
mkdir -p .github/scripts/oracle/cosmian-kms

docker compose -f "$COMPOSE_FILE" --profile oracle up -d --wait

# Copy the Cosmian PKCS#11 library from the KMS image into Oracle
bash .github/scripts/oracle/set_hsm.sh

docker compose -f "$COMPOSE_FILE" --profile oracle down --remove-orphans || true
echo "Oracle TDE HSM test completed successfully"

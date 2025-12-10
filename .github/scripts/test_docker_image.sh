#!/bin/bash

set -ex

# Detect FIPS vs non-FIPS from image name
# FIPS images: ghcr.io/cosmian/kms-fips or cosmian-kms:*-fips
# Non-FIPS images: ghcr.io/cosmian/kms or cosmian-kms:*-non-fips
if [[ "${DOCKER_IMAGE_NAME:-}" == *"-fips"* ]] || [[ "${DOCKER_IMAGE_NAME:-}" == *"kms-fips"* ]]; then
    COMPOSE_FILE=".github/scripts/docker-compose-authentication-tests-fips.yml"
    echo "Detected FIPS image: ${DOCKER_IMAGE_NAME}"
else
    COMPOSE_FILE=".github/scripts/docker-compose-authentication-tests-non-fips.yml"
    echo "Detected non-FIPS image: ${DOCKER_IMAGE_NAME}"
fi

# Config paths
CLI_VERSION="1.5.2"
CONFIG=~/.cosmian/cosmian-no-tls.toml
TLS_CONFIG=~/.cosmian/cosmian-tls.toml
KMS_URL_HTTP="http://0.0.0.0:9998"
KMS_URL_HTTPS="https://0.0.0.0:9999"

# Cert paths
CA_CERT="test_data/certificates/client_server/ca/ca.crt"
CLIENT_CERT="test_data/certificates/client_server/owner/owner.client.acme.com.crt"
CLIENT_KEY="test_data/certificates/client_server/owner/owner.client.acme.com.key"
CLIENT_PKCS12_PATH="test_data/certificates/client_server/owner/owner.client.acme.com.p12"

set -ex

# install cli (skip if already available or if cargo is not available)
if ! command -v cosmian >/dev/null 2>&1; then
    if command -v cargo >/dev/null 2>&1; then
        cargo install cosmian_cli --version "$CLI_VERSION"
    else
        echo "Warning: cargo not available and cosmian CLI not installed. Skipping CLI installation."
        echo "Some tests may be skipped."
    fi
fi

cosmian --version

# update cli conf
mkdir -p ~/.cosmian
touch $CONFIG $TLS_CONFIG

echo '
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "'$KMS_URL_HTTP'"
' | tee $CONFIG

echo '
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "'$KMS_URL_HTTPS'"
accept_invalid_certs = true
ssl_client_pkcs12_path = "'$CLIENT_PKCS12_PATH'"
ssl_client_pkcs12_password = "password"
' | tee $TLS_CONFIG

# Ensure any previous stacks are down to avoid port conflicts
docker compose -f .github/scripts/docker-compose-with-conf.yml down || true
docker compose -f .github/scripts/docker-compose-authentication-tests-fips.yml down || true
docker compose -f .github/scripts/docker-compose-authentication-tests-non-fips.yml down || true

# Run docker containers
docker compose -f "$COMPOSE_FILE" up -d

# Wait for the containers to be ready
echo "Waiting for KMS servers to start..."
sleep 15

# Show container status
echo "Container status:"
docker compose -f "$COMPOSE_FILE" ps -a

# Verify servers are responding
echo "Using compose file: $COMPOSE_FILE"
echo "Docker image name: ${DOCKER_IMAGE_NAME:-not set}"

# Check no-authentication server (port 9998)
for i in {1..30}; do
    if curl -s -f http://127.0.0.1:9998/ui/index.html >/dev/null 2>&1; then
        echo "KMS server on port 9998 is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: KMS server on port 9998 failed to start after 30 attempts"
        echo "Compose file being used: $COMPOSE_FILE"
        echo "Showing container status:"
        docker compose -f "$COMPOSE_FILE" ps -a
        echo "Showing container logs:"
        docker compose -f "$COMPOSE_FILE" logs
        exit 1
    fi
    sleep 1
done

# Check TLS server (port 9999) - give it more time if needed
echo "Checking TLS server on port 9999..."
for i in {1..30}; do
    if curl -k -s -f https://127.0.0.1:9999/ui/index.html >/dev/null 2>&1; then
        echo "TLS server on port 9999 is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: TLS server on port 9999 failed to start after 30 attempts"
        echo "Showing tls-authentication container logs:"
        docker compose -f "$COMPOSE_FILE" logs tls-authentication
        echo "Showing container status:"
        docker compose -f "$COMPOSE_FILE" ps -a
        echo "Showing container logs:"
        docker compose -f "$COMPOSE_FILE" logs
        exit 1
    fi
    sleep 1
done

# Check TLS13 server (port 10000) - give it more time if needed
echo "Checking TLS13 server on port 10000..."
for i in {1..30}; do
    if curl -k -s -f https://127.0.0.1:10000/ui/index.html >/dev/null 2>&1; then
        echo "TLS13 server on port 10000 is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: TLS13 server on port 10000 failed to start after 30 attempts"
        echo "Showing tls13-authentication container logs:"
        docker compose -f "$COMPOSE_FILE" logs tls13-authentication
        echo "Showing container status:"
        docker compose -f "$COMPOSE_FILE" ps -a
        exit 1
    fi
    sleep 1
done

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
cosmian -c "$CONFIG" kms sym keys create
cosmian -c "$TLS_CONFIG" kms sym keys create

# Test TLS on HTTP server with default options
openssl_test "127.0.0.1:9999" "tls1_2"
openssl_test "127.0.0.1:9999" "tls1_3"

# Test TLS socket server with default options
openssl_test "127.0.0.1:5696" "tls1_2"
openssl_test "127.0.0.1:5696" "tls1_3"

# Test TLS on HTTP server with specific TLS1.3
test_tls_failure "127.0.0.1:10000" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port 10000"
openssl_test "127.0.0.1:10000" "tls1_3"

# Test TLS socket server with specific TLS1.3
test_tls_failure "127.0.0.1:5697" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port 5697"
openssl_test "127.0.0.1:5697" "tls1_3"

# Test UI endpoints
curl -I http://127.0.0.1:9998/ui/index.html
curl --insecure -I https://127.0.0.1:9999/ui/index.html
curl --insecure -I https://127.0.0.1:10000/ui/index.html

# === Config-file based compose test ===
# Use COSMIAN_KMS_CONF with mounted pkg/kms.toml and verify UI
echo "Running config-based compose test (.github/scripts/docker-compose-with-conf.yml)"
docker compose -f .github/scripts/docker-compose-authentication-tests-fips.yml down || true
docker compose -f .github/scripts/docker-compose-authentication-tests-non-fips.yml down || true
docker compose -f .github/scripts/docker-compose-with-conf.yml up -d --force-recreate --remove-orphans

# Probe UI on 9998
for i in {1..30}; do
    if curl -s -f http://127.0.0.1:9998/ui/index.html >/dev/null 2>&1; then
        echo "Config-based KMS server on port 9998 is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Config-based KMS server on port 9998 failed to start"
        docker compose -f .github/scripts/docker-compose-with-conf.yml ps -a || true
        docker compose -f .github/scripts/docker-compose-with-conf.yml logs || true
        exit 1
    fi
    sleep 1
done

# Show brief logs for verification
docker compose -f .github/scripts/docker-compose-with-conf.yml logs --tail=120 || true

# Tear down config-based stack
docker compose -f .github/scripts/docker-compose-with-conf.yml down || true

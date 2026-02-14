#!/bin/bash

set -exuo pipefail

pick_free_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
PY
        return 0
    fi

    if command -v python >/dev/null 2>&1; then
        python - <<'PY'
import socket
s = socket.socket()
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
PY
        return 0
    fi

    echo "ERROR: python3 (or python) is required to pick free ports" >&2
    exit 1
}

pick_unique_port() {
    local p
    while true; do
        p="$(pick_free_port)"
        if [[ -z "${USED_PORTS[${p}]:-}" ]]; then
            USED_PORTS[${p}]=1
            echo "${p}"
            return 0
        fi
    done
}

# Prefer cargo-installed binaries if present.
export PATH="$HOME/.cargo/bin:$PATH"

cleanup() {
    set +e
    docker compose -f .github/scripts/docker-compose-with-conf.yml down --remove-orphans || true
    docker compose -f .github/scripts/docker-compose-authentication-tests-fips.yml down --remove-orphans || true
    docker compose -f .github/scripts/docker-compose-authentication-tests-non-fips.yml down --remove-orphans || true
    docker compose -f .github/scripts/docker-compose.example.yml down --remove-orphans || true
    docker compose -f .github/scripts/docker-compose-with-load-balancer.yml down --remove-orphans || true
}

trap cleanup EXIT

# Detect FIPS vs non-FIPS from image name robustly
# FIPS images: ghcr.io/cosmian/kms-fips or cosmian-kms:* -fips (not -non-fips)
# Non-FIPS images: ghcr.io/cosmian/kms or cosmian-kms:* -non-fips
if [[ "${DOCKER_IMAGE_NAME:-}" == *"-non-fips"* ]]; then
    COMPOSE_FILE=".github/scripts/docker-compose-authentication-tests-non-fips.yml"
    echo "Detected non-FIPS image: ${DOCKER_IMAGE_NAME}"
elif [[ "${DOCKER_IMAGE_NAME:-}" == *"-fips"* ]] || [[ "${DOCKER_IMAGE_NAME:-}" == *"kms-fips"* ]]; then
    COMPOSE_FILE=".github/scripts/docker-compose-authentication-tests-fips.yml"
    echo "Detected FIPS image: ${DOCKER_IMAGE_NAME}"
else
    # Default to non-FIPS if ambiguous
    COMPOSE_FILE=".github/scripts/docker-compose-authentication-tests-non-fips.yml"
    echo "Image variant ambiguous; defaulting to non-FIPS: ${DOCKER_IMAGE_NAME}"
fi

# Config paths
# NOTE: keep in sync with crates.io versions that compile on CI runners.
# cosmian_cli 1.8.0 currently fails to build due to upstream dependency version
# skew (multiple cosmian_crypto_core versions). 1.8.1 fixes this.
CLI_VERSION="${CLI_VERSION:-1.8.1}"
CONFIG=~/.cosmian/cosmian-no-tls.toml
TLS_CONFIG=~/.cosmian/cosmian-tls.toml

# Pick dynamic host ports to avoid collisions (e.g. local systemd service on 9998).
declare -A USED_PORTS=()
export KMS_HTTP_PORT="${KMS_HTTP_PORT:-$(pick_unique_port)}"
export KMS_TLS_PORT="${KMS_TLS_PORT:-$(pick_unique_port)}"
export KMS_TLS13_PORT="${KMS_TLS13_PORT:-$(pick_unique_port)}"
export KMS_SOCKET_TLS_PORT="${KMS_SOCKET_TLS_PORT:-$(pick_unique_port)}"
export KMS_SOCKET_TLS13_PORT="${KMS_SOCKET_TLS13_PORT:-$(pick_unique_port)}"
export LB_PORT="${LB_PORT:-$(pick_unique_port)}"

KMS_URL_HTTP="http://0.0.0.0:${KMS_HTTP_PORT}"
KMS_URL_HTTPS="https://0.0.0.0:${KMS_TLS_PORT}"

# Cert paths
CA_CERT="test_data/certificates/client_server/ca/ca.crt"
CLIENT_CERT="test_data/certificates/client_server/owner/owner.client.acme.com.crt"
CLIENT_KEY="test_data/certificates/client_server/owner/owner.client.acme.com.key"
CLIENT_PKCS12_PATH="test_data/certificates/client_server/owner/owner.client.acme.com.p12"

# Install/ensure the desired CLI version.
# CI runners may have no preinstalled `cosmian`, while developer machines can.
# If the binary exists but is the wrong version, upgrade it (when cargo is available).
COSMIAN_BIN=""
if command -v cosmian >/dev/null 2>&1; then
    COSMIAN_BIN="$(command -v cosmian)"
fi

if command -v cargo >/dev/null 2>&1; then
    current_version=""
    if [[ -n "$COSMIAN_BIN" ]]; then
        current_version="$($COSMIAN_BIN --version 2>/dev/null | awk '{print $2}' || true)"
    fi

    if [[ "$current_version" != "$CLI_VERSION" ]]; then
        cargo install cosmian_cli --locked --version "$CLI_VERSION" --force
        hash -r
        COSMIAN_BIN="$(command -v cosmian)"
    fi
else
    if [[ -z "$COSMIAN_BIN" ]]; then
        echo "Warning: cargo not available and cosmian CLI not installed. Skipping CLI-dependent tests."
        echo "Some tests may be skipped."
    fi
fi

if [[ -z "$COSMIAN_BIN" ]]; then
    echo "Warning: cosmian CLI not available; skipping CLI-dependent tests."
else
    $COSMIAN_BIN --version
fi

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
cleanup

# Run docker containers
docker compose -f "$COMPOSE_FILE" up -d

# Fail fast if any service isn't running (compose can return 0 even on partial startup)
services="$(docker compose -f "$COMPOSE_FILE" config --services)"
for service in $services; do
    cid="$(docker compose -f "$COMPOSE_FILE" ps -q "$service" || true)"
    if [[ -z "$cid" ]]; then
        echo "ERROR: no container id for service '$service'" >&2
        docker compose -f "$COMPOSE_FILE" ps -a || true
        docker compose -f "$COMPOSE_FILE" logs || true
        exit 1
    fi
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
    if [[ "$status" != "running" ]]; then
        echo "ERROR: service '$service' is not running (status=$status)" >&2
        docker compose -f "$COMPOSE_FILE" ps -a || true
        docker compose -f "$COMPOSE_FILE" logs "$service" || true
        exit 1
    fi
done

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
    if curl -s -f "http://127.0.0.1:${KMS_HTTP_PORT}/ui/index.html" >/dev/null 2>&1; then
        echo "KMS server on port ${KMS_HTTP_PORT} is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: KMS server on port ${KMS_HTTP_PORT} failed to start after 30 attempts"
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
echo "Checking TLS server on port ${KMS_TLS_PORT}..."
for i in {1..30}; do
    if curl -k -s -f "https://127.0.0.1:${KMS_TLS_PORT}/ui/index.html" >/dev/null 2>&1; then
        echo "TLS server on port ${KMS_TLS_PORT} is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: TLS server on port ${KMS_TLS_PORT} failed to start after 30 attempts"
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
echo "Checking TLS13 server on port ${KMS_TLS13_PORT}..."
for i in {1..30}; do
    if curl -k -s -f "https://127.0.0.1:${KMS_TLS13_PORT}/ui/index.html" >/dev/null 2>&1; then
        echo "TLS13 server on port ${KMS_TLS13_PORT} is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: TLS13 server on port ${KMS_TLS13_PORT} failed to start after 30 attempts"
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
if [[ -n "$COSMIAN_BIN" ]]; then
    $COSMIAN_BIN -c "$CONFIG" kms sym keys create
    $COSMIAN_BIN -c "$TLS_CONFIG" kms sym keys create
else
    echo "Skipping key creation: cosmian CLI not available"
fi

# Test TLS on HTTP server with default options
openssl_test "127.0.0.1:${KMS_TLS_PORT}" "tls1_2"
openssl_test "127.0.0.1:${KMS_TLS_PORT}" "tls1_3"

# Test TLS socket server with default options
openssl_test "127.0.0.1:${KMS_SOCKET_TLS_PORT}" "tls1_2"
openssl_test "127.0.0.1:${KMS_SOCKET_TLS_PORT}" "tls1_3"

# Test TLS on HTTP server with specific TLS1.3
test_tls_failure "127.0.0.1:${KMS_TLS13_PORT}" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port ${KMS_TLS13_PORT}"
openssl_test "127.0.0.1:${KMS_TLS13_PORT}" "tls1_3"

# Test TLS socket server with specific TLS1.3
test_tls_failure "127.0.0.1:${KMS_SOCKET_TLS13_PORT}" "tls1_2" "TLS 1.2 correctly rejected on TLS 1.3-only port ${KMS_SOCKET_TLS13_PORT}"
openssl_test "127.0.0.1:${KMS_SOCKET_TLS13_PORT}" "tls1_3"

# Test UI endpoints
curl -I "http://127.0.0.1:${KMS_HTTP_PORT}/ui/index.html"
curl --insecure -I "https://127.0.0.1:${KMS_TLS_PORT}/ui/index.html"
curl --insecure -I "https://127.0.0.1:${KMS_TLS13_PORT}/ui/index.html"

# === Config-file based compose test ===
# Use COSMIAN_KMS_CONF with mounted pkg/kms.toml and verify UI
echo "Running config-based compose test (.github/scripts/docker-compose-with-conf.yml)"
docker compose -f .github/scripts/docker-compose-authentication-tests-fips.yml down || true
docker compose -f .github/scripts/docker-compose-authentication-tests-non-fips.yml down || true
docker compose -f .github/scripts/docker-compose-with-conf.yml up -d --force-recreate --remove-orphans

# Probe UI on 9998
for i in {1..30}; do
    if curl -s -f "http://127.0.0.1:${KMS_HTTP_PORT}/ui/index.html" >/dev/null 2>&1; then
        echo "Config-based KMS server on port ${KMS_HTTP_PORT} is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Config-based KMS server on port ${KMS_HTTP_PORT} failed to start"
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

# === Example docker-compose smoke test ===
# Run the minimal example compose to ensure a default container boots.
echo "Running example compose test (.github/scripts/docker-compose.example.yml)"
docker compose -f .github/scripts/docker-compose.example.yml down || true
docker compose -f .github/scripts/docker-compose.example.yml up -d --force-recreate --remove-orphans

# Probe server on 9998 (health if available, else a KMIP probe)
for i in {1..30}; do
    if curl -s -f "http://127.0.0.1:${KMS_HTTP_PORT}/health" >/dev/null 2>&1; then
        echo "Example-compose KMS server on port ${KMS_HTTP_PORT} is ready (/health)"
        break
    fi
    if curl -s -X POST -H "Content-Type: application/json" -d '{}' "http://127.0.0.1:${KMS_HTTP_PORT}/kmip/2_1" >/dev/null 2>&1; then
        echo "Example-compose KMS server on port ${KMS_HTTP_PORT} is ready (/kmip probe)"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Example-compose KMS server on port ${KMS_HTTP_PORT} failed to start"
        docker compose -f .github/scripts/docker-compose.example.yml ps -a || true
        docker compose -f .github/scripts/docker-compose.example.yml logs || true
        exit 1
    fi
    sleep 1
done

docker compose -f .github/scripts/docker-compose.example.yml logs --tail=120 || true
docker compose -f .github/scripts/docker-compose.example.yml down || true

# === Load balancer shutdown behavior test ===
echo "Running load balancer shutdown test (.github/scripts/test_lb_kms_shutdown.sh)"
bash .github/scripts/test_lb_kms_shutdown.sh

# Ensure LB stack is cleaned up after the test
docker compose -f .github/scripts/docker-compose-with-load-balancer.yml down || true

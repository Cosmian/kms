#!/bin/bash

# Config paths
CLI_VERSION="1.2.0"
CONFIG=~/.cosmian/cosmian-no-tls.toml
TLS_CONFIG=~/.cosmian/cosmian-tls.toml
KMS_URL_HTTP="http://0.0.0.0:9998"
KMS_URL_HTTPS="https://0.0.0.0:9999"

# Cert paths
CA_CERT="test_data/client_server/ca/ca.crt"
CLIENT_CERT="test_data/client_server/owner/owner.client.acme.com.crt"
CLIENT_KEY="test_data/client_server/owner/owner.client.acme.com.key"
CLIENT_PKCS12_PATH="test_data/client_server/owner/owner.client.acme.com.p12"

set -ex

# install cli
sudo apt update && sudo apt install -y wget
wget "https://package.cosmian.com/cli/$CLI_VERSION/ubuntu-24.04/cosmian-cli_$CLI_VERSION-1_amd64.deb"
sudo apt install ./"cosmian-cli_$CLI_VERSION-1_amd64.deb"
cosmian --version

# update cli conf
sudo mkdir ~/.cosmian
sudo touch $CONFIG $TLS_CONFIG

echo '
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "'$KMS_URL_HTTP'"
' | sudo tee $CONFIG

echo '
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "'$KMS_URL_HTTPS'"
accept_invalid_certs = true
ssl_client_pkcs12_path = "'$CLIENT_PKCS12_PATH'"
ssl_client_pkcs12_password = "password"
' | sudo tee $TLS_CONFIG

# Run docker containers
docker compose -f .github/scripts/docker-compose-authentication-tests.yml up -d

# Wait for the containers to be ready
sleep 10

# Function to test OpenSSL connections
openssl_test() {
  local host_port=$1
  local tls_version=$2
  echo "Testing $host_port with TLS $tls_version"
  openssl s_client -showcerts -debug -"$tls_version" -connect "$host_port" \
    -CAfile "$CA_CERT" \
    -cert "$CLIENT_CERT" \
    -key "$CLIENT_KEY"
}

# Create symmetric keys
cosmian -c "$CONFIG" kms sym keys create
cosmian -c "$TLS_CONFIG" kms sym keys create

# Test UI endpoints
curl -I http://127.0.0.1:9998/ui/index.html
curl --insecure -I https://127.0.0.1:9999/ui/index.html

# Test TLS HTTPS server
openssl_test "127.0.0.1:9999" "tls1_2"
openssl_test "127.0.0.1:9999" "tls1_3"

# Test TLS socket server
openssl_test "127.0.0.1:5696" "tls1_2"
openssl_test "127.0.0.1:5696" "tls1_3"

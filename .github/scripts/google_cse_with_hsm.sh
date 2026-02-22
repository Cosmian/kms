#!/bin/bash

set -exo pipefail

# Run KMS server:
# cargo run -p cosmian_kms_server --features non-fips -- --hsm-slot 0 --hsm-password 12345678 --hsm-model utimaco --tls-p12-file test_data/certificates/client_server/server/kmserver.acme.com.p12 --tls-p12-password password --port 9999

TLS_CONFIG=~/.cosmian/cosmian-tls.toml
KMS_URL_HTTPS="https://0.0.0.0:9999"
EXT_DIR="test_data/certificates/gmail_cse"
USER="john.doe@acme.com"
CSE_KEY="documentation/docs/google_cse/original_kms_cse_key.demo.key.json"
# Cert paths
CLIENT_PKCS12_PATH="test_data/certificates/client_server/owner/owner.client.acme.com.p12"

# update cli conf
mkdir -p ~/.cosmian
touch $TLS_CONFIG

echo '
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "'$KMS_URL_HTTPS'"
accept_invalid_certs = true
ssl_client_pkcs12_path = "'$CLIENT_PKCS12_PATH'"
ssl_client_pkcs12_password = "password"
' | tee $TLS_CONFIG

# COSMIAN="cosmian -c $TLS_CONFIG"
COSMIAN="cargo run -p ckms -- -c $TLS_CONFIG"


$COSMIAN kms certificates certify \
  --certificate-id acme_root_ca \
  --generate-key-pair \
  --algorithm rsa4096 \
  --subject-name "CN=ACME Root CA,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
  --days 3650 \
  --certificate-extensions $EXT_DIR/example_root.ext

# Generate intermediate certificate
$COSMIAN kms certificates certify \
  --certificate-id acme_intermediate_ca \
  --issuer-certificate-id acme_root_ca \
  --generate-key-pair \
  --algorithm rsa4096 \
  --subject-name "CN=ACME S/MIME intermediate,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
  --days 1825 \
  --certificate-extensions $EXT_DIR/example_intermediate.ext

# Generate End Issuer certificate
$COSMIAN kms certificates certify \
  --certificate-id john.doe@acme.com \
  --issuer-certificate-id acme_intermediate_ca \
  --generate-key-pair \
  --algorithm rsa4096 \
  --subject-name "CN=john.doe@acme.com,OU=IT,O=ACME,L=San Francisco,ST=California,C=US" \
  --days 365 \
  --certificate-extensions $EXT_DIR/example_user.ext

# Using a HSM wrapping key
HSM_KEY_ID="hsm::0::wrapping_key_$(openssl rand -hex 8)"
GOOGLE_KEY_ID="google_cse"
$COSMIAN kms sym keys create "$HSM_KEY_ID"
# CryptographicUsageMask is already set to 2108 for the imported CSE key
$COSMIAN kms sym keys import -f json-ttlv -r -t "$GOOGLE_KEY_ID" -w "$HSM_KEY_ID" "$CSE_KEY" "$GOOGLE_KEY_ID"
# In case of imported a key without CryptographicUsageMask (ie. 0), add --key-usage wrap-key --key-usage encrypt --key-usage decrypt

# Or using plaintext Google key (uncomment next lines)
# GOOGLE_KEY_ID="google_cse_$(openssl rand -hex 8)"
# $COSMIAN kms sym keys create "$GOOGLE_KEY_ID"

# Reusing the created certificate
$COSMIAN kms google key-pairs create \
  --cse-key-id "$GOOGLE_KEY_ID" \
  --leaf-certificate-id $USER \
  -s "CN=$USER,OU=IT,O=ACME,L=San Francisco,ST=California,C=US" \
  $USER --dry-run

# Or generating on the fly the end-user certificate
ISSUER_PRIVATE_KEY_ID=$(COSMIAN_KMS_CLI_FORMAT=json $COSMIAN kms attributes get \
  --id acme_intermediate_ca | jq -r .attributes.PrivateKeyLink)
$COSMIAN kms google key-pairs create \
  --cse-key-id "$GOOGLE_KEY_ID" \
  -i "$ISSUER_PRIVATE_KEY_ID" \
  -e $EXT_DIR/example_user.ext \
  -s "CN=$USER,OU=IT,O=ACME,L=San Francisco,ST=California,C=US" \
  $USER --dry-run

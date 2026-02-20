#!/bin/bash
# Generates mTLS test data for Azure EKM integration testing.
# Run from any location; files are generated next to this script.
# Expects to be launched from the repo root OR via run_azure_ekm_mtls_test.sh.
set -e

# Resolve the directory where this script lives (= the data directory)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Repo root is two levels up: .github/scripts/azure_ekm_test_data -> repo root
REPO_ROOT=$(cd "${SCRIPT_DIR}/../../.." && pwd)
# Path to data dir relative to repo root (used in kms.toml so KMS can resolve at startup)
DATA_DIR_REL=".github/scripts/azure_ekm_test_data"

echo "Generating test data in ${SCRIPT_DIR}..."
cd "${SCRIPT_DIR}"

# --- 1. Server CA and Certificate ---
echo "Generating Server CA..."
openssl req -x509 -newkey rsa:4096 -keyout server_ca_key.pem -out server_ca_cert.pem \
    -sha256 -days 365 -nodes -subj "/CN=Azure EKM Server CA"

echo "Generating Server Certificate Request..."
openssl req -new -newkey rsa:4096 -keyout server_key.pem -out server.csr \
    -nodes -subj "/CN=localhost"

echo "Signing Server Certificate with Server CA..."
cat > server_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA server_ca_cert.pem -CAkey server_ca_key.pem \
    -CAcreateserial -out server_cert.pem -days 365 -sha256 -extfile server_ext.cnf

echo "Packing Server PKCS#12..."
openssl pkcs12 -export -out server.p12 \
    -inkey server_key.pem -in server_cert.pem -passout pass:password

# --- 2. Client CA and Certificate (simulates Azure Managed HSM) ---
echo "Generating Client (HSM) CA..."
openssl req -x509 -newkey rsa:4096 -keyout client_ca_key.pem -out client_ca_cert.pem \
    -sha256 -days 365 -nodes -subj "/CN=Azure EKM Client CA"

echo "Generating Client Certificate Request..."
openssl req -new -newkey rsa:4096 -keyout client_key.pem -out client.csr \
    -nodes -subj "/CN=Azure Managed HSM"

echo "Signing Client Certificate with Client CA..."
openssl x509 -req -in client.csr -CA client_ca_cert.pem -CAkey client_ca_key.pem \
    -CAcreateserial -out client_cert.pem -days 365 -sha256

# --- 3. Finished generating certificates ---

echo "Done. Test data generated in ${SCRIPT_DIR}"

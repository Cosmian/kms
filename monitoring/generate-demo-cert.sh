#!/usr/bin/env bash
set -euo pipefail


# ─────────────────────────────────────────────────────────────
# Generate a long-lived demo PKCS#12 certificate for Cosmian KMS
# Output: ./certs/kms.p12 (used in docker-compose)
# ─────────────────────────────────────────────────────────────

CERTS_DIR="./certs"
P12_FILE="${CERTS_DIR}/kms.p12"
KEY_FILE="${CERTS_DIR}/kms-demo.key"
CRT_FILE="${CERTS_DIR}/kms-demo.crt"

if [ -f .env ]; then
  # Load environment variables from .env (specifically KMS_P12_PASSWORD)
  export $(grep -v '^#' .env | xargs)
fi
P12_PASSWORD="${KMS_P12_PASSWORD}"   # must match --tls-p12-password in docker-compose

# 1) Ensure target directory exists
mkdir -p "${CERTS_DIR}"

# 2) Generate private key + self-signed certificate (valid 10 years)
openssl req -x509 -newkey rsa:4096 \
  -keyout "${KEY_FILE}" \
  -out "${CRT_FILE}" \
  -sha256 \
  -days 3650 \
  -nodes \
  -subj "/CN=cosmian-kms-demo"

# 3) Create PKCS#12 bundle used by KMS
openssl pkcs12 -export \
  -inkey "${KEY_FILE}" \
  -in "${CRT_FILE}" \
  -out "${P12_FILE}" \
  -name "cosmian-kms-demo" \
  -password pass:${P12_PASSWORD}

echo "PKCS#12 demo certificate generated at: ${P12_FILE}"
echo "Password: ${P12_PASSWORD}"

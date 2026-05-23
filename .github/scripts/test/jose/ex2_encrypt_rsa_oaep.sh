#!/usr/bin/env bash
# Example 2 — RSA-OAEP-256 key wrapping + AES-GCM content encryption / decryption
# Usage: KMS_URL=http://localhost:9998 bash ex2_encrypt_rsa_oaep.sh
set -euo pipefail

KMS_URL="${KMS_URL:-http://localhost:9998}"

echo "==> 1. Create an RSA-2048 key pair"
KEYS=$(curl -sf -X POST "$KMS_URL/v1/crypto/keys" \
  -H 'Content-Type: application/json' \
  -d '{"kty":"RSA","bits":2048}')
KID=$(echo "$KEYS" | jq -r '.kid')
KID_PUB=$(echo "$KEYS" | jq -r '.kid_public')
echo "    kid (private): $KID"
echo "    kid_public:    $KID_PUB"

echo "==> 2. Encrypt with RSA-OAEP-256 (public key)"
DATA_B64=$(printf 'Secret message' | base64 | tr '+/' '-_' | tr -d '=')
JWE=$(curl -sf -X POST "$KMS_URL/v1/crypto/encrypt" \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KID_PUB\",\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"data\":\"$DATA_B64\"}")
echo "    encrypted_key (first 40 chars): $(echo "$JWE" | jq -r '.encrypted_key' | head -c 40)..."

echo "==> 3. Decrypt (kid in protected header resolves to private key automatically)"
RESULT=$(curl -sf -X POST "$KMS_URL/v1/crypto/decrypt" \
  -H 'Content-Type: application/json' \
  -d "$JWE")
PLAINTEXT=$(echo "$RESULT" | jq -r '.data | @base64d')
echo "    plaintext: $PLAINTEXT"
[ "$PLAINTEXT" = "Secret message" ] || {
  echo "ERROR: plaintext mismatch"
  exit 1
}

echo "==> 4. Clean up (cascades to the linked public key)"
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$KMS_URL/v1/crypto/keys/$KID")
echo "    DELETE $KID → HTTP $HTTP_STATUS"
[ "$HTTP_STATUS" = "204" ] || {
  echo "ERROR: expected 204, got $HTTP_STATUS"
  exit 1
}

echo "OK: RSA-OAEP-256 + A256GCM encrypt/decrypt round-trip passed"

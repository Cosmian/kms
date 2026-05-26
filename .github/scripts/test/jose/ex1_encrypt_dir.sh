#!/usr/bin/env bash
# Example 1 — Direct AES-GCM encryption / decryption
# Usage: KMS_URL=http://localhost:9998 bash ex1_encrypt_dir.sh
set -euo pipefail

KMS_URL="${KMS_URL:-http://localhost:9998}"

echo "==> 1. Create a 256-bit AES key"
KID=$(curl -sf -X POST "$KMS_URL/v1/crypto/keys" \
  -H 'Content-Type: application/json' \
  -d '{"kty":"oct","alg":"A256GCM"}' | jq -r '.kid')
echo "    kid: $KID"

echo "==> 2. Encrypt"
DATA_B64=$(printf 'Hello KMS!' | base64 | tr '+/' '-_' | tr -d '=')
JWE=$(curl -sf -X POST "$KMS_URL/v1/crypto/encrypt" \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KID\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"$DATA_B64\"}")
echo "    JWE: $JWE" | head -c 200
echo

echo "==> 3. Decrypt"
RESULT=$(curl -sf -X POST "$KMS_URL/v1/crypto/decrypt" \
  -H 'Content-Type: application/json' \
  -d "$JWE")
PLAINTEXT=$(echo "$RESULT" | jq -r '.data | @base64d')
echo "    plaintext: $PLAINTEXT"
[ "$PLAINTEXT" = "Hello KMS!" ] || {
  echo "ERROR: plaintext mismatch"
  exit 1
}

echo "==> 4. Clean up"
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$KMS_URL/v1/crypto/keys/$KID")
echo "    DELETE $KID → HTTP $HTTP_STATUS"
[ "$HTTP_STATUS" = "204" ] || {
  echo "ERROR: expected 204, got $HTTP_STATUS"
  exit 1
}

echo "OK: Direct AES-GCM encrypt/decrypt round-trip passed"

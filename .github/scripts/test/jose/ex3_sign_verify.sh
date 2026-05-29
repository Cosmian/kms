#!/usr/bin/env bash
# Example 3 — RSA RS256 sign / verify
# Usage: KMS_URL=http://localhost:9998 bash ex3_sign_verify.sh
set -euo pipefail

KMS_URL="${KMS_URL:-http://localhost:9998}"

echo "==> 1. Create an RSA-2048 key pair (RS256)"
KEYS=$(curl -sf -X POST "$KMS_URL/v1/crypto/keys" \
  -H 'Content-Type: application/json' \
  -d '{"kty":"RSA","alg":"RS256"}')
KID=$(echo "$KEYS" | jq -r '.kid')
echo "    kid (private): $KID"

echo "==> 2. Sign"
DATA_B64=$(printf 'data to sign' | base64 | tr '+/' '-_' | tr -d '=')
SIGN_RESP=$(curl -sf -X POST "$KMS_URL/v1/crypto/sign" \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KID\",\"alg\":\"RS256\",\"data\":\"$DATA_B64\"}")
echo "    signature (first 40 chars): $(echo "$SIGN_RESP" | jq -r '.signature' | head -c 40)..."

echo "==> 3. Verify"
VERIFY_BODY=$(jq -n \
  --argjson sign "$SIGN_RESP" \
  --arg data "$DATA_B64" \
  '{protected: $sign.protected, data: $data, signature: $sign.signature}')
VERIFY_RESP=$(curl -sf -X POST "$KMS_URL/v1/crypto/verify" \
  -H 'Content-Type: application/json' \
  -d "$VERIFY_BODY")
echo "    verify response: $VERIFY_RESP"
VALID=$(echo "$VERIFY_RESP" | jq -r '.valid')
[ "$VALID" = "true" ] || {
  echo "ERROR: expected valid=true, got $VALID"
  exit 1
}

echo "==> 4. Clean up"
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$KMS_URL/v1/crypto/keys/$KID")
echo "    DELETE $KID → HTTP $HTTP_STATUS"
[ "$HTTP_STATUS" = "204" ] || {
  echo "ERROR: expected 204, got $HTTP_STATUS"
  exit 1
}

echo "OK: RSA RS256 sign/verify passed"

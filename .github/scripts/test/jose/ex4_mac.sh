#!/usr/bin/env bash
# Example 4 — HMAC-SHA256 MAC compute / verify
# Usage: KMS_URL=http://localhost:9998 bash ex4_mac.sh
set -euo pipefail

KMS_URL="${KMS_URL:-http://localhost:9998}"

echo "==> 1. Create an HMAC-SHA256 key"
KID=$(curl -sf -X POST "$KMS_URL/v1/crypto/keys" \
  -H 'Content-Type: application/json' \
  -d '{"kty":"oct","alg":"HS256"}' | jq -r '.kid')
echo "    kid: $KID"

echo "==> 2. Compute MAC"
DATA_B64=$(printf 'message' | base64 | tr '+/' '-_' | tr -d '=')
MAC_RESP=$(curl -sf -X POST "$KMS_URL/v1/crypto/mac" \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KID\",\"alg\":\"HS256\",\"data\":\"$DATA_B64\"}")
MAC_VALUE=$(echo "$MAC_RESP" | jq -r '.mac')
echo "    mac: $MAC_VALUE"

echo "==> 3. Verify MAC"
VERIFY_RESP=$(curl -sf -X POST "$KMS_URL/v1/crypto/mac" \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KID\",\"alg\":\"HS256\",\"data\":\"$DATA_B64\",\"mac\":\"$MAC_VALUE\"}")
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

echo "OK: HMAC-SHA256 MAC compute/verify passed"

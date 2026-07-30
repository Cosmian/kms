#!/usr/bin/env bash
# kms_setup.sh — Provision an AppRole on the Eviden KMS auth-verifier
#
# Usage:
#   ROLE_NAME=my-spire ./kms_setup.sh
#
# Optional overrides (env vars):
#   AUTH_URL, KMS_URL, ADMIN_USER, ADMIN_PASSWORD, AUTH_CA, COOKIE_JAR
#
set -euo pipefail

: "${AUTH_URL:=https://poc-mcds.cosmian.dev:8443}"
: "${KMS_URL:=https://poc-mcds.cosmian.dev}"
: "${ADMIN_USER:=admin}"
: "${ADMIN_PASSWORD:=change_me}"
: "${ROLE_NAME:=${1:-spire-prod}}"
: "${AUTH_CA:=auth-ca.pem}"
: "${COOKIE_JAR:=/tmp/auth-admin-cookies.txt}"

GREEN="\033[0;32m"; RED="\033[0;31m"; NC="\033[0m"
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

###############################################################################
echo "=== Step 0: Download auth-verifier CA cert ==="
openssl s_client -connect "${AUTH_URL#https://}" -showcerts </dev/null 2>/dev/null \
  | python3 -c "
import sys, re
certs = re.findall(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
                   sys.stdin.read(), re.DOTALL)
print(certs[1])
" > "$AUTH_CA"
SUBJECT=$(openssl x509 -in "$AUTH_CA" -noout -subject 2>/dev/null)
[[ -s "$AUTH_CA" ]] && pass "CA cert saved ($SUBJECT)" || fail "CA cert is empty"

###############################################################################
echo ""
echo "=== Step 1: Admin login ==="
RESP=$(curl -s -c "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -u "$ADMIN_USER:$ADMIN_PASSWORD" \
  -H "Content-Type: application/json" -d "{}" \
  "$AUTH_URL/login?realm=_")
echo "$RESP"
[[ "$RESP" == *Authenticated* ]] && pass "Admin authenticated" || fail "Admin login failed"

###############################################################################
echo ""
echo "=== Step 2: Create AppRole '$ROLE_NAME' ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -H "Content-Type: application/json" \
  -d '{"token_ttl":3600,"secret_id_ttl":0,"token_policies":["default"],"bind_secret_id":true}' \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME")
echo "HTTP $HTTP_CODE"
[[ "$HTTP_CODE" =~ ^(200|204)$ ]] && pass "AppRole created" || fail "AppRole creation failed (HTTP $HTTP_CODE)"

###############################################################################
echo ""
echo "=== Step 3: Read role_id ==="
ROLE_RESP=$(curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME/role-id")
echo "$ROLE_RESP"
VAULT_APPROLE_ID=$(echo "$ROLE_RESP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
echo "role_id: $VAULT_APPROLE_ID"
[[ "$VAULT_APPROLE_ID" =~ ^[0-9a-f-]{36}$ ]] && pass "role_id is valid UUID" || fail "role_id invalid: $VAULT_APPROLE_ID"

###############################################################################
echo ""
echo "=== Step 4: Generate secret_id ==="
SECRET_RESP=$(curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -H "Content-Type: application/json" -d '{"ttl":0,"num_uses":0}' \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME/secret-id")
echo "$SECRET_RESP"
VAULT_APPROLE_SECRET_ID=$(echo "$SECRET_RESP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
echo "secret_id: $VAULT_APPROLE_SECRET_ID"
[[ "$VAULT_APPROLE_SECRET_ID" =~ ^[0-9a-f-]{36}$ ]] && pass "secret_id is valid UUID" || fail "secret_id invalid"

###############################################################################
echo ""
echo "=== Step 5: AppRole login via KMS ==="
LOGIN_RESP=$(curl -s \
  -X POST -H "Content-Type: application/json" \
  -d "{\"role_id\":\"$VAULT_APPROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}" \
  "$KMS_URL/v1/auth/approle/login")
echo "$LOGIN_RESP"
TOKEN=$(echo "$LOGIN_RESP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
echo "Token: $TOKEN"
[[ "$TOKEN" == hvs.* ]] && pass "KMS token obtained" || fail "Token invalid: $TOKEN"

###############################################################################
echo ""
echo "=== Step 6: Lookup-self (verify identity) ==="
LOOKUP=$(curl -s -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/auth/token/lookup-self")
echo "$LOOKUP"
ENTITY=$(echo "$LOOKUP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['entity_id'])")
[[ "$ENTITY" == "$ROLE_NAME" ]] && pass "entity_id = $ENTITY" || fail "entity_id mismatch: $ENTITY"

###############################################################################
echo ""
echo "=== SUMMARY ==="
echo "role_id:   $VAULT_APPROLE_ID"
echo "secret_id: $VAULT_APPROLE_SECRET_ID"
echo "token:     $TOKEN"
echo ""
echo "Add to your SPIRE server.conf:"
echo "  vault_addr = \"$KMS_URL\""
echo "  approle_auth_mount_point = \"approle\""
echo ""
echo "Set environment before starting SPIRE:"
echo "  export VAULT_APPROLE_ID=\"$VAULT_APPROLE_ID\""
echo "  export VAULT_APPROLE_SECRET_ID=\"$VAULT_APPROLE_SECRET_ID\""
echo ""
echo -e "${GREEN}=== ALL STEPS PASSED ===${NC}"

#!/usr/bin/env bash
# =============================================================================
# kms_setup.sh — Eviden KMS / SPIRE PoC quick-start
# =============================================================================
#
# This script walks through the full customer setup on poc-mcds.cosmian.dev:
#   1. Download the auth-verifier CA certificate
#   2. Create an AppRole on the auth-verifier (ckms vault approle)
#   3. Test AppRole login via the KMS proxy (curl)
#   4. Verify token and transit key access
#
# Prerequisites:
#   - ckms (Cosmian KMS CLI) on PATH  →  https://github.com/Cosmian/kms/releases
#   - curl, python3
#
# Usage:
#   ROLE_NAME=my-spire ./kms_setup.sh
# =============================================================================
set -euo pipefail

KMS_URL="${KMS_URL:-https://poc-mcds.cosmian.dev}"
AUTH_URL="${AUTH_URL:-https://poc-mcds.cosmian.dev:8443}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-change_me}"
ROLE_NAME="${ROLE_NAME:-spire-prod}"
AUTH_CA="${AUTH_CA:-auth-ca.pem}"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
ok() { echo -e "${GREEN}✔ $*${NC}"; }
info() { echo -e "${CYAN}→ $*${NC}"; }
die() {
  echo -e "${RED}✖ $*${NC}" >&2
  exit 1
}

echo -e "${BOLD}=== Eviden KMS / SPIRE PoC setup ===${NC}"
echo "  KMS:          $KMS_URL"
echo "  Auth-verifier: $AUTH_URL"
echo "  AppRole name: $ROLE_NAME"
echo ""

# ── Step 1: Download auth-verifier CA ─────────────────────────────────────────
if [[ ! -f "$AUTH_CA" ]]; then
  info "Downloading auth-verifier CA certificate → $AUTH_CA"
  # The auth CA is self-signed; disable verification only for this bootstrap step
  curl -sk "$AUTH_URL/public/ca-chain" -o "$AUTH_CA" 2>/dev/null ||
    die "Cannot reach $AUTH_URL — check network / VPN"
  ok "Auth CA saved to $AUTH_CA"
else
  ok "Auth CA already present: $AUTH_CA"
fi

# Verify the CA cert looks valid
openssl x509 -in "$AUTH_CA" -noout -subject 2>/dev/null ||
  die "$AUTH_CA does not look like a valid PEM certificate"

# ── Step 2: Create AppRole on the auth-verifier ────────────────────────────────
info "Creating AppRole '$ROLE_NAME' on auth-verifier…"
ckms vault approle create-role "$ROLE_NAME" \
  --auth-verifier-url "$AUTH_URL" \
  --auth-verifier-ca-cert "$AUTH_CA" \
  --admin-user "$ADMIN_USER" \
  --admin-password "$ADMIN_PASSWORD" \
  --token-ttl 3600
ok "AppRole '$ROLE_NAME' created (or already exists)"

# ── Step 3: Read role_id ───────────────────────────────────────────────────────
info "Reading role_id…"
VAULT_APPROLE_ID=$(ckms vault approle get-role-id "$ROLE_NAME" \
  --auth-verifier-url "$AUTH_URL" \
  --auth-verifier-ca-cert "$AUTH_CA" \
  --admin-user "$ADMIN_USER" \
  --admin-password "$ADMIN_PASSWORD" |
  tr -d '[:space:]')
[[ -n "$VAULT_APPROLE_ID" ]] || die "Failed to retrieve role_id"
ok "role_id: $VAULT_APPROLE_ID"

# ── Step 4: Generate secret_id ────────────────────────────────────────────────
info "Generating secret_id…"
SECRET_OUTPUT=$(ckms vault approle generate-secret-id "$ROLE_NAME" \
  --auth-verifier-url "$AUTH_URL" \
  --auth-verifier-ca-cert "$AUTH_CA" \
  --admin-user "$ADMIN_USER" \
  --admin-password "$ADMIN_PASSWORD")
VAULT_APPROLE_SECRET_ID=$(echo "$SECRET_OUTPUT" | awk '/^secret_id:/{print $2}')
[[ -n "$VAULT_APPROLE_SECRET_ID" ]] || die "Failed to generate secret_id"
ok "secret_id generated (single-use, store securely)"

# ── Step 5: Test AppRole login via KMS ────────────────────────────────────────
info "Testing AppRole login via KMS proxy ($KMS_URL)…"
LOGIN_RESP=$(curl -sf \
  -X POST -H "Content-Type: application/json" \
  -d "{\"role_id\":\"$VAULT_APPROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}" \
  "$KMS_URL/v1/auth/approle/login") ||
  die "AppRole login failed — check KMS is running and vault_api_enabled = true"

TOKEN=$(echo "$LOGIN_RESP" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
[[ "$TOKEN" == hvs.* ]] || die "Unexpected token format: $TOKEN"
ok "Token obtained: ${TOKEN:0:20}…"

# ── Step 6: Validate token via lookup-self ─────────────────────────────────────
info "Validating token via lookup-self…"
ENTITY=$(curl -sf -H "X-Vault-Token: $TOKEN" \
  "$KMS_URL/v1/auth/token/lookup-self" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['data']['entity_id'])")
[[ "$ENTITY" == "$ROLE_NAME" ]] || die "entity_id mismatch: got '$ENTITY', want '$ROLE_NAME'"
ok "entity_id: $ENTITY ✓"

# ── Step 7: List transit keys (empty on first use) ────────────────────────────
info "Listing transit keys (namespace: $ROLE_NAME)…"
KEYS_RESP=$(curl -sf -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/transit/keys")
ok "Transit keys response: $KEYS_RESP"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== Ready to configure SPIRE ===${NC}"
echo ""
echo "  Set these environment variables before starting your SPIRE server:"
echo ""
echo -e "  ${BOLD}export VAULT_APPROLE_ID=\"$VAULT_APPROLE_ID\"${NC}"
echo -e "  ${BOLD}export VAULT_APPROLE_SECRET_ID=\"$VAULT_APPROLE_SECRET_ID\"${NC}"
echo ""
echo "  SPIRE server.conf excerpt:"
echo ""
cat <<HCL
  UpstreamAuthority "vault" {
    plugin_data {
      vault_addr   = "$KMS_URL"
      approle_auth {
        approle_auth_mount_point = "approle"
      }
      pki_mount_point = "pki"
    }
  }
HCL
echo ""
echo -e "${GREEN}All checks passed.${NC}"

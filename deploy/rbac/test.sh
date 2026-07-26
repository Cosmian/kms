#!/usr/bin/env bash
# ===========================================================================
# test.sh — Smoke-test the Cosmian KMS RBAC + Keycloak stack
#
# Usage:
#   ./test.sh
#   KMS_URL=https://myhost:9998 KC_URL=https://myhost:8180 ./test.sh
#
# Requirements: curl, jq (or python3 as fallback), bash >= 4
# ===========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ──────────────────────────────────────────────────────────
CA="${CA:-${SCRIPT_DIR}/certs/ca.crt}"
KMS_URL="${KMS_URL:-https://localhost:9998}"
KC_URL="${KC_URL:-https://localhost:8180}"
KC_REALM="${KC_REALM:-kms}"
KC_CLIENT="${KC_CLIENT:-cosmian-kms}"

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# JSON decode helper (jq preferred, python3 fallback)
json() {
    if command -v jq &>/dev/null; then
        jq -r "$1" <<< "$2"
    else
        python3 -c "import sys,json; print(json.loads('''$2''')$1)" 2>/dev/null || echo ""
    fi
}

# ── Helpers ────────────────────────────────────────────────────────────────
get_token() {
    local user="$1" pass="$2"
    curl -sf --cacert "$CA" \
        -X POST "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
        -d "client_id=${KC_CLIENT}&grant_type=password&username=${user}&password=${pass}" \
        | (command -v jq &>/dev/null && jq -r .access_token || python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
}

decode_roles() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d. -f2 | awk '{n=length($0)%4; if(n==2)$0=$0"=="; else if(n==3)$0=$0"="; print}' | base64 -d 2>/dev/null)
    command -v jq &>/dev/null \
        && jq -r '.realm_access.roles[]' <<< "$payload" \
        || python3 -c "import json; d=json.loads('${payload}'); print('\n'.join(d.get('realm_access',{}).get('roles',[])))"
}

kms() {
    local token="$1"; shift
    curl -sf --cacert "$CA" -H "Authorization: Bearer ${token}" "$@"
}

# ── Pre-flight ─────────────────────────────────────────────────────────────
echo "==========================================================="
echo "  Cosmian KMS RBAC stack — smoke tests"
echo "  KMS : ${KMS_URL}"
echo "  KC  : ${KC_URL}/realms/${KC_REALM}"
echo "  CA  : ${CA}"
echo "==========================================================="
echo ""

if [[ ! -f "$CA" ]]; then
    fail "CA cert not found at ${CA} — run 'docker compose up' first"
    exit 1
fi

# ── Test 1: KMS health (unauthenticated) ───────────────────────────────────
info "Test 1: KMS health endpoint"
resp=$(curl -sf --cacert "$CA" "${KMS_URL}/health" 2>&1) || { fail "KMS not reachable"; exit 1; }
if echo "$resp" | grep -q '"status"'; then
    pass "KMS is UP — $resp"
else
    fail "Unexpected health response: $resp"
fi
echo ""

# ── Test 2: Keycloak OIDC discovery ────────────────────────────────────────
info "Test 2: Keycloak OIDC discovery for realm '${KC_REALM}'"
resp=$(curl -sf --cacert "$CA" "${KC_URL}/realms/${KC_REALM}/.well-known/openid-configuration" 2>&1) || { fail "Keycloak not reachable"; exit 1; }
if echo "$resp" | grep -q "issuer"; then
    pass "Keycloak realm '${KC_REALM}' is reachable"
else
    fail "Unexpected discovery response: ${resp:0:200}"
fi
echo ""

# ── Test 3–6: Per-user token + role + KMS access ───────────────────────────
run_user_test() {
    local label="$1" user="$2" password="$3" expected_role="$4" can_create="$5"

    info "Test: user '${user}' (expected role: ${expected_role})"

    # Get token
    token=$(get_token "$user" "$password") || { fail "${label}: token request failed"; return; }
    [[ -n "$token" && "$token" != "null" ]] || { fail "${label}: empty token"; return; }
    pass "${label}: token issued"

    # Decode roles
    roles=$(decode_roles "$token")
    if echo "$roles" | grep -q "$expected_role"; then
        pass "${label}: token contains role '${expected_role}' (roles: $(echo $roles | tr '\n' ','))"
    else
        fail "${label}: expected role '${expected_role}' not found in token (got: $(echo $roles | tr '\n' ','))"
    fi

    # KMS health with token
    resp=$(kms "$token" "${KMS_URL}/health" 2>&1) || { fail "${label}: authenticated health call failed"; return; }
    if echo "$resp" | grep -q '"status"'; then
        pass "${label}: authenticated KMS health OK"
    else
        fail "${label}: authenticated health returned: ${resp:0:200}"
    fi

    # List owned objects (all roles can do this)
    http_code=$(curl -o /dev/null -sw "%{http_code}" --cacert "$CA" \
        -H "Authorization: Bearer ${token}" "${KMS_URL}/access/owned" 2>/dev/null)
    if [[ "$http_code" == "200" ]]; then
        pass "${label}: GET /access/owned → 200"
    else
        fail "${label}: GET /access/owned → HTTP ${http_code}"
    fi

    echo ""
}

run_user_test "Admin"    "admin@cosmian.com"    "Admin1234!"    "admin"    "yes"
run_user_test "Operator" "operator@cosmian.com" "Operator1234!" "operator" "yes"
run_user_test "Auditor"  "auditor@cosmian.com"  "Auditor1234!"  "auditor"  "no"
run_user_test "Readonly" "readonly@cosmian.com" "Readonly1234!" "readonly" "no"

# ── Test 7: Invalid credentials → no token ─────────────────────────────────
info "Test 7: Invalid credentials should be rejected by Keycloak"
bad=$(curl -s --cacert "$CA" \
    -X POST "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
    -d "client_id=${KC_CLIENT}&grant_type=password&username=admin@cosmian.com&password=WRONG" \
    2>&1)
if echo "$bad" | grep -q "Unauthorized\|invalid_grant\|401"; then
    pass "Invalid credentials correctly rejected"
else
    fail "Expected rejection, got: ${bad:0:200}"
fi
echo ""

# ── Test 8: No token → 401 from KMS ────────────────────────────────────────
info "Test 8: Missing token should return 401 from KMS"
http_code=$(curl -o /dev/null -sw "%{http_code}" --cacert "$CA" \
    "${KMS_URL}/access/owned" 2>/dev/null)
if [[ "$http_code" == "401" ]]; then
    pass "No token → HTTP 401 (Unauthorized)"
else
    fail "Expected 401, got HTTP ${http_code}"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────────
echo "==========================================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}"
echo "==========================================================="
[[ $FAIL -eq 0 ]]

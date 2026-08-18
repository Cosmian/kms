#!/usr/bin/env bash
# Verify the FIXED auth image (cosmian-auth-verifier:0.2.1) end-to-end through
# APISIX forward-auth. Unlike the original reproduce.sh, this uses the correct
# client contract for the fixed server:
#   * the admin API (create realm / create userpass) is expected to SUCCEED
#   * userpass creation sends the PLAINTEXT password bytes (the server hashes)
#   * a non-admin user must be able to log in and pass the forward-auth gate
set -uo pipefail
cd "$(dirname "$0")/.."

ADMIN_KEY="repro-admin-key-12345"
ADMIN_API="http://localhost:9180/apisix/admin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
info() { echo -e "  ${YELLOW}INFO${NC} $1"; }
step() { echo ""; echo "== $1 =="; }
FAILURES=0

curl_retry() {
  local out attempt
  for attempt in 1 2 3 4 5; do
    out=$(curl "$@" 2>/dev/null)
    [ -n "$out" ] && [ "$out" != "000" ] && break
    sleep 1
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
step "0. Configure APISIX routes"
# ---------------------------------------------------------------------------
curl_retry -s -X PUT "$ADMIN_API/upstreams/1" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{"type":"roundrobin","nodes":{"auth-server:8443":1},"scheme":"https"}' >/dev/null
curl_retry -s -X PUT "$ADMIN_API/upstreams/2" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{"type":"roundrobin","nodes":{"protected-app:80":1}}' >/dev/null
curl_retry -s -X PUT "$ADMIN_API/routes/1" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{"uri":"/*","hosts":["auth.repro.local"],"upstream_id":"1","plugins":{"proxy-rewrite":{"scheme":"https"}}}' >/dev/null
curl_retry -s -X PUT "$ADMIN_API/routes/2" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{
    "uri":"/*","hosts":["protected.repro.local"],"upstream_id":"2",
    "plugins":{"forward-auth":{
      "uri":"https://auth-server:8443/whoami?realm=test-realm",
      "request_headers":["Cookie"],
      "client_headers":["Set-Cookie","WWW-Authenticate"],
      "ssl_verify":false,"timeout":5000}}}' >/dev/null
info "Routes configured"
sleep 2

# ---------------------------------------------------------------------------
step "1. Protected route without a session cookie -> expect 401"
# ---------------------------------------------------------------------------
CODE=$(curl_retry -sk -o /dev/null -w "%{http_code}" --resolve protected.repro.local:9080:127.0.0.1 \
  "http://protected.repro.local:9080/")
[ "$CODE" = "401" ] && pass "GET protected/ (no cookie) -> 401" || { fail "GET protected/ (no cookie) -> $CODE (expected 401)"; FAILURES=$((FAILURES+1)); }

# ---------------------------------------------------------------------------
step "2. Login as the seeded admin (realm=_) -> expect 200 + session cookie"
# ---------------------------------------------------------------------------
LOGIN_RESP=$(curl_retry -sk -D - --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=_" -u "admin:change_me" \
  -H "Content-Type: application/json" -d '{}')
ADMIN_COOKIE=$(echo "$LOGIN_RESP" | grep -i '^set-cookie:' | sed 's/^set-cookie: //I' | cut -d';' -f1 | tr -d '\r')
if echo "$LOGIN_RESP" | grep -q "200" && [ -n "$ADMIN_COOKIE" ]; then
  pass "Admin login -> 200, cookie captured"
else
  fail "Admin login failed"; echo "$LOGIN_RESP" | head -20; FAILURES=$((FAILURES+1))
fi

# ---------------------------------------------------------------------------
step "3. FIX CHECK -- create a realm via the admin API -> expect success (no 500)"
# ---------------------------------------------------------------------------
REALM_RESP=$(curl_retry -sk -w $'\n%{http_code}' --resolve auth.repro.local:9080:127.0.0.1 \
  -H "Cookie: $ADMIN_COOKIE" -X POST "http://auth.repro.local:9080/admins/realms" \
  -H "Content-Type: application/json" \
  -d '{"id":"test-realm","auth_params":{"jwt_params":null,"username_password_params":{"allow_expired_passwords":true}},"session_max_age_seconds":28800,"session_max_stale_age_seconds":3600}')
REALM_CODE=$(echo "$REALM_RESP" | tail -1); REALM_BODY=$(echo "$REALM_RESP" | sed '$d')
if echo "$REALM_BODY" | grep -q "client_certificate"; then
  fail "POST /admins/realms -> $REALM_CODE (BUG 1 still present: client_certificate)"; FAILURES=$((FAILURES+1))
elif [ "$REALM_CODE" = "200" ] || [ "$REALM_CODE" = "201" ]; then
  pass "POST /admins/realms -> $REALM_CODE (realm created via admin API)"
else
  info "POST /admins/realms -> $REALM_CODE body: $REALM_BODY"
  # A 409/idempotent-conflict on re-run is acceptable; anything else is a failure.
  echo "$REALM_BODY" | grep -qiE "exist|conflict" && pass "realm already exists (idempotent re-run)" || { fail "unexpected realm-create result"; FAILURES=$((FAILURES+1)); }
fi

# ---------------------------------------------------------------------------
step "4. FIX CHECK -- create a normal user via the admin API (PLAINTEXT password)"
# ---------------------------------------------------------------------------
PASSWORD_BYTES=$(python3 -c "import json;print(json.dumps(list(b'testpass123')))")
USER_RESP=$(curl_retry -sk -w $'\n%{http_code}' --resolve auth.repro.local:9080:127.0.0.1 \
  -H "Cookie: $ADMIN_COOKIE" -X POST "http://auth.repro.local:9080/realms/test-realm/userpass" \
  -H "Content-Type: application/json" \
  -d "{\"realm\":\"test-realm\",\"username\":\"testuser\",\"password\":$PASSWORD_BYTES,\"change_password\":false,\"roles\":[]}")
USER_CODE=$(echo "$USER_RESP" | tail -1); USER_BODY=$(echo "$USER_RESP" | sed '$d')
if echo "$USER_BODY" | grep -q "client_certificate"; then
  fail "POST /realms/test-realm/userpass -> $USER_CODE (BUG 1: client_certificate)"; FAILURES=$((FAILURES+1))
elif [ "$USER_CODE" = "200" ] || [ "$USER_CODE" = "201" ]; then
  pass "POST /realms/test-realm/userpass -> $USER_CODE (user created via admin API, plaintext contract)"
else
  info "body: $USER_BODY"
  echo "$USER_BODY" | grep -qiE "exist|conflict" && pass "user already exists (idempotent re-run)" || { fail "POST userpass -> $USER_CODE"; FAILURES=$((FAILURES+1)); }
fi

# ---------------------------------------------------------------------------
step "5. FIX CHECK (BUG 2) -- login as the non-admin user -> expect 200 + cookie"
# ---------------------------------------------------------------------------
USER_LOGIN=$(curl_retry -sk -D - --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=test-realm" -u "testuser:testpass123" \
  -H "Content-Type: application/json" -d '{}')
USER_COOKIE=$(echo "$USER_LOGIN" | grep -i '^set-cookie:' | sed 's/^set-cookie: //I' | cut -d';' -f1 | tr -d '\r')
if echo "$USER_LOGIN" | grep -qi "Authentication service error"; then
  fail "non-admin login -> 401 'Authentication service error' (BUG 2 still present)"; FAILURES=$((FAILURES+1))
elif echo "$USER_LOGIN" | grep -q "200" && [ -n "$USER_COOKIE" ]; then
  pass "non-admin login -> 200, cookie captured (BUG 2 FIXED)"
else
  fail "non-admin login unexpected result"; echo "$USER_LOGIN" | head -20; FAILURES=$((FAILURES+1))
fi

# ---------------------------------------------------------------------------
step "6. E2E -- protected route via APISIX with the NON-ADMIN cookie -> expect 200"
# ---------------------------------------------------------------------------
CODE=$(curl_retry -sk -o /dev/null -w "%{http_code}" --resolve protected.repro.local:9080:127.0.0.1 \
  -H "Cookie: $USER_COOKIE" "http://protected.repro.local:9080/")
[ "$CODE" = "200" ] && pass "GET protected/ with non-admin cookie -> 200 (forward-auth E2E works)" \
  || { fail "GET protected/ with non-admin cookie -> $CODE (expected 200)"; FAILURES=$((FAILURES+1)); }

# ---------------------------------------------------------------------------
echo ""
echo "======================================================================"
if [ "$FAILURES" -eq 0 ]; then
  echo -e " ${GREEN}ALL CHECKS PASSED${NC} — fix validated end-to-end through APISIX forward-auth."
else
  echo -e " ${RED}${FAILURES} CHECK(S) FAILED${NC}"
fi
echo "======================================================================"
exit "$FAILURES"

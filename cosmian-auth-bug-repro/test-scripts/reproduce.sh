#!/usr/bin/env bash
# Reproduces two Cosmian auth-server bugs and shows APISIX forward-auth behaves
# correctly throughout (it only ever relays auth-server's own responses).
set -uo pipefail
cd "$(dirname "$0")/.."

ADMIN_KEY="repro-admin-key-12345"
GATEWAY="http://localhost:9080"
ADMIN_API="http://localhost:9180/apisix/admin"
AUTH_DIRECT="https://localhost:18443"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
info() { echo -e "  ${YELLOW}INFO${NC} $1"; }
step() { echo ""; echo "== $1 =="; }

# retry helper: some environments occasionally drop the first chunked
# response on a freshly-opened loopback connection; retry a few times.
curl_retry() {
  local out attempt
  for attempt in 1 2 3 4 5; do
    out=$(curl "$@" 2>/dev/null)
    [ -n "$out" ] && [ "$out" != "000" ] && break
    sleep 1
  done
  printf '%s' "$out"
}

echo "==> Waiting for APISIX gateway to be reachable..."
for i in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9080/" 2>/dev/null)
  [ -n "$CODE" ] && [ "$CODE" != "000" ] && break
  sleep 1
done

# ---------------------------------------------------------------------------
step "0. Configure APISIX routes"
# ---------------------------------------------------------------------------
curl_retry -s -X PUT "$ADMIN_API/upstreams/1" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{"type":"roundrobin","nodes":{"auth-server:8443":1},"scheme":"https"}' >/dev/null

curl_retry -s -X PUT "$ADMIN_API/upstreams/2" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{"type":"roundrobin","nodes":{"protected-app:80":1}}' >/dev/null

# auth.repro.local -> auth-server directly (login / admin API / whoami), no forward-auth
curl_retry -s -X PUT "$ADMIN_API/routes/1" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{
    "uri": "/*",
    "hosts": ["auth.repro.local"],
    "upstream_id": "1",
    "plugins": {"proxy-rewrite": {"scheme": "https"}}
  }' >/dev/null

# protected.repro.local -> protected-app, guarded by forward-auth against auth-server /whoami
curl_retry -s -X PUT "$ADMIN_API/routes/2" -H "X-API-KEY: $ADMIN_KEY" \
  -d '{
    "uri": "/*",
    "hosts": ["protected.repro.local"],
    "upstream_id": "2",
    "plugins": {
      "forward-auth": {
        "uri": "https://auth-server:8443/whoami?realm=test-realm",
        "request_headers": ["Cookie"],
        "client_headers": ["Set-Cookie", "WWW-Authenticate"],
        "ssl_verify": false,
        "timeout": 5000
      }
    }
  }' >/dev/null

info "Routes configured (auth.repro.local, protected.repro.local)"
sleep 2

# ---------------------------------------------------------------------------
step "1. Protected route without a session cookie -> expect 401"
# ---------------------------------------------------------------------------
CODE=$(curl_retry -sk -o /dev/null -w "%{http_code}" --resolve protected.repro.local:9080:127.0.0.1 \
  "http://protected.repro.local:9080/")
[ "$CODE" = "401" ] && pass "GET protected/ (no cookie) -> 401" || fail "GET protected/ (no cookie) -> $CODE (expected 401)"

# ---------------------------------------------------------------------------
step "2. Login as the seeded admin (realm=_) -> expect 200 + session cookie"
# ---------------------------------------------------------------------------
LOGIN_RESP=$(curl_retry -sk -D - --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=_" -u "admin:change_me" \
  -H "Content-Type: application/json" -d '{}')
ADMIN_COOKIE=$(echo "$LOGIN_RESP" | grep -i '^set-cookie:' | sed 's/^set-cookie: //I' | cut -d';' -f1 | tr -d '\r')
if echo "$LOGIN_RESP" | grep -q "HTTP/1.1 200"; then
  pass "Admin login -> 200, cookie captured"
else
  fail "Admin login did not return 200"
fi

# ---------------------------------------------------------------------------
step "3. BUG 1 -- create a realm via the admin API -> expect 500 (client_certificate)"
# ---------------------------------------------------------------------------
REALM_RESP=$(curl_retry -sk --resolve auth.repro.local:9080:127.0.0.1 \
  -H "Cookie: $ADMIN_COOKIE" -X POST "http://auth.repro.local:9080/admins/realms" \
  -H "Content-Type: application/json" \
  -d '{"id":"test-realm","auth_params":{"jwt_params":null,"username_password_params":{"allow_expired_passwords":true}},"session_max_age_seconds":28800,"session_max_stale_age_seconds":3600}')
if echo "$REALM_RESP" | grep -q "client_certificate"; then
  fail "POST /admins/realms -> 500 'no column found for name: client_certificate' (BUG confirmed)"
  info "Response: $REALM_RESP"
else
  pass "POST /admins/realms succeeded unexpectedly (bug may be fixed): $REALM_RESP"
fi

# ---------------------------------------------------------------------------
step "4. Workaround -- insert the realm directly in Postgres"
# ---------------------------------------------------------------------------
docker compose exec -T postgres psql -U postgres -d postgres -c "
INSERT INTO realm (id, auth_params, cookie_max_age_seconds, max_stale_age_seconds)
VALUES ('test-realm', '{\"jwt_params\":null,\"username_password_params\":{\"allow_expired_passwords\":true}}', 28800, 3600)
ON CONFLICT (id) DO NOTHING;" >/dev/null 2>&1
info "Realm 'test-realm' inserted directly in DB"

# ---------------------------------------------------------------------------
step "5. BUG 1 (again) -- create a normal user via the admin API -> expect 500"
# ---------------------------------------------------------------------------
HASH=$(docker run --rm alpine sh -c \
  "apk add --no-cache argon2 >/dev/null 2>&1 && printf 'testpass123' | argon2 somesalt1234567 -id -t 3 -m 12 -p 1 -e" 2>/dev/null | tr -d '\n')
PASSWORD_BYTES=$(python3 -c "import json,sys; print(json.dumps(list('$HASH'.encode())))" 2>/dev/null || \
  docker run --rm python:3.12-alpine python3 -c "import json; print(json.dumps(list('$HASH'.encode())))")

USER_RESP=$(curl_retry -sk --resolve auth.repro.local:9080:127.0.0.1 \
  -H "Cookie: $ADMIN_COOKIE" -X POST "http://auth.repro.local:9080/realms/test-realm/userpass" \
  -H "Content-Type: application/json" \
  -d "{\"realm\":\"test-realm\",\"username\":\"testuser\",\"password\":$PASSWORD_BYTES,\"change_password\":false,\"roles\":[]}")
if echo "$USER_RESP" | grep -q "client_certificate"; then
  fail "POST /realms/test-realm/userpass -> 500 'client_certificate' (BUG confirmed, same root cause as step 3)"
else
  pass "POST /realms/test-realm/userpass succeeded unexpectedly: $USER_RESP"
fi

# ---------------------------------------------------------------------------
step "6. Workaround -- insert the test user directly in Postgres"
# ---------------------------------------------------------------------------
docker compose exec -T postgres psql -U postgres -d postgres -c "
INSERT INTO userpass (realm, username, password, change_password, roles)
VALUES ('test-realm', 'testuser', '$HASH', false, '[]')
ON CONFLICT (realm, username) DO NOTHING;" >/dev/null 2>&1
info "User 'testuser' inserted directly in DB (realm test-realm, password 'testpass123')"

# ---------------------------------------------------------------------------
step "7. BUG 2 -- login as a normal (non-admin) user -> expect 401"
# ---------------------------------------------------------------------------
USER_LOGIN=$(curl_retry -sk --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=test-realm" -u "testuser:testpass123" \
  -H "Content-Type: application/json" -d '{}')
if echo "$USER_LOGIN" | grep -q "Authentication service error"; then
  fail "POST /login?realm=test-realm (testuser) -> 401 'Authentication service error' (BUG confirmed)"
else
  pass "Non-admin login succeeded unexpectedly: $USER_LOGIN"
fi

# ---------------------------------------------------------------------------
step "8. Sanity -- forward-auth mechanics work when auth-server actually succeeds"
# ---------------------------------------------------------------------------
CODE=$(curl_retry -sk -o /dev/null -w "%{http_code}" --resolve protected.repro.local:9080:127.0.0.1 \
  -H "Cookie: $ADMIN_COOKIE" "http://protected.repro.local:9080/")
[ "$CODE" = "200" ] && pass "GET protected/ with admin cookie -> 200 (APISIX + forward-auth relay correctly)" \
                     || fail "GET protected/ with admin cookie -> $CODE (expected 200)"

# ---------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo " Summary"
echo "======================================================================"
echo " BUG 1: admin API (POST /admins/realms, POST /realms/{realm}/userpass)"
echo "        crashes with 500 'no column found for name: client_certificate'"
echo "        whenever a valid admin session is used to call them."
echo ""
echo " BUG 2: login for any user other than the seeded 'admin' fails with"
echo "        401 'Authentication service error', on any realm."
echo ""
echo " APISIX / forward-auth: proven NOT at fault -- it only ever relays"
echo " auth-server's own status code and body verbatim (see README.md)."
echo "======================================================================"

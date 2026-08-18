# Procedure — start the stack and test a working APISIX forward-auth request

This runbook brings up the reproduction stack against the **fixed** auth image
(`cosmian-auth-verifier:0.2.1`) and verifies that an APISIX `forward-auth`
request works end-to-end: a protected route is denied without a session and
allowed once a **non-admin** user has logged in.

All commands are run from the repository folder:

```bash
cd cosmian-auth-bug-repro
```

> **Docker permissions.** The commands below call `docker` directly. If you get
> `permission denied while trying to connect to the Docker daemon socket`, either
> add your user to the `docker` group once (`sudo usermod -aG docker "$USER"`,
> then log out and back in), or prefix each `docker …` command with
> `sg docker -c '…'`.

---

## 1. Prerequisites

- Docker Engine + Docker Compose v2 (`docker compose`, not `docker-compose`)
- `openssl`, `curl`, `python3`
- The fixed image `cosmian-auth-verifier:0.2.1` loaded into Docker.

Check the image is present:

```bash
docker image inspect cosmian-auth-verifier:0.2.1 >/dev/null 2>&1 \
  && echo "image present" || echo "image MISSING — build it (step 1a)"
```

### 1a. (Only if the image is missing) build it via Nix

Requires Nix on PATH. From the auth-server source tree:

```bash
cd ../authentication
bash .github/scripts/nix.sh docker --load     # builds and `docker load`s cosmian-auth-verifier:<version>
cd ../cosmian-auth-bug-repro
```

This compiles the auth server and produces `cosmian-auth-verifier:0.2.1`.

---

## 2. Generate TLS + JWT keys and pin the image

Run once (skips if keys already exist):

```bash
if [ ! -f tls/tls.crt ]; then
  mkdir -p tls jwt
  openssl ecparam -genkey -name prime256v1 -noout -out tls/tls.key.ec
  openssl pkcs8 -topk8 -nocrypt -in tls/tls.key.ec -out tls/tls.key
  openssl req -x509 -new -key tls/tls.key.ec -out tls/tls.crt -days 3650 -nodes \
    -subj "/CN=auth-server" -addext "subjectAltName=DNS:auth-server,DNS:localhost"
  rm -f tls/tls.key.ec
  openssl ecparam -genkey -name prime256v1 -noout -out jwt/jwt_ec_private.pem
  openssl pkcs8 -topk8 -nocrypt -in jwt/jwt_ec_private.pem -out jwt/jwt_ec_private_pkcs8.pem
  openssl ec -in jwt/jwt_ec_private.pem -pubout -out jwt/jwt_ec_public.pem
  rm -f jwt/jwt_ec_private.pem
fi
echo "AUTH_SERVER_IMAGE=cosmian-auth-verifier:0.2.1" > .env
```

The persistent JWT signing keys are required so session cookies survive across
requests (without them the server generates an ephemeral key per request and
every cookie fails signature validation).

---

## 3. Start the stack

`docker-compose.override.yml` is picked up automatically and swaps in the fixed
image with its native entrypoint.

```bash
docker compose up -d
```

Wait for the auth server to answer:

```bash
for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost:18443/public/version)
  [ "$code" = "200" ] && { echo "auth-server ready"; break; }
  sleep 2
done
```

Services:

| Service | Address |
|---|---|
| APISIX gateway | `http://localhost:9080` |
| APISIX admin API | `http://localhost:9180` (key `repro-admin-key-12345`) |
| auth-server (direct) | `https://localhost:18443` |

---

## 4. Automated check (recommended)

Runs the full flow (route setup, admin login, realm + non-admin user creation,
non-admin login, and the forward-auth-protected request) and prints PASS/FAIL:

```bash
bash scripts/verify_fixed.sh
```

Expected final line:

```
 ALL CHECKS PASSED — fix validated end-to-end through APISIX forward-auth.
```

If you only want the manual forward-auth demonstration, continue with step 5.

---

## 5. Manual forward-auth test

### 5.1 Configure the two APISIX routes (idempotent)

```bash
ADMIN_API="http://localhost:9180/apisix/admin"; KEY="repro-admin-key-12345"

curl -s -X PUT "$ADMIN_API/upstreams/1" -H "X-API-KEY: $KEY" \
  -d '{"type":"roundrobin","nodes":{"auth-server:8443":1},"scheme":"https"}' >/dev/null
curl -s -X PUT "$ADMIN_API/upstreams/2" -H "X-API-KEY: $KEY" \
  -d '{"type":"roundrobin","nodes":{"protected-app:80":1}}' >/dev/null

# auth.repro.local -> auth-server (login / admin API), no forward-auth
curl -s -X PUT "$ADMIN_API/routes/1" -H "X-API-KEY: $KEY" \
  -d '{"uri":"/*","hosts":["auth.repro.local"],"upstream_id":"1","plugins":{"proxy-rewrite":{"scheme":"https"}}}' >/dev/null

# protected.repro.local -> nginx, GUARDED by forward-auth against auth-server /whoami
curl -s -X PUT "$ADMIN_API/routes/2" -H "X-API-KEY: $KEY" \
  -d '{"uri":"/*","hosts":["protected.repro.local"],"upstream_id":"2",
       "plugins":{"forward-auth":{
         "uri":"https://auth-server:8443/whoami?realm=test-realm",
         "request_headers":["Cookie"],
         "client_headers":["Set-Cookie","WWW-Authenticate"],
         "ssl_verify":false,"timeout":5000}}}' >/dev/null
```

### 5.2 Forward-auth denies an unauthenticated request → 401

```bash
curl -s -o /dev/null -w "no-cookie -> %{http_code}\n" \
  --resolve protected.repro.local:9080:127.0.0.1 \
  http://protected.repro.local:9080/
# expect: no-cookie -> 401
```

### 5.3 Create a realm + a non-admin user (admin session)

```bash
# Admin login -> capture session cookie
ADMIN_COOKIE=$(curl -sk -D - --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=_" -u "admin:change_me" \
  -H "Content-Type: application/json" -d '{}' \
  | grep -i '^set-cookie:' | sed 's/^set-cookie: //I' | cut -d';' -f1 | tr -d '\r')

# Create realm 'test-realm'
curl -sk --resolve auth.repro.local:9080:127.0.0.1 -H "Cookie: $ADMIN_COOKIE" \
  -X POST "http://auth.repro.local:9080/admins/realms" -H "Content-Type: application/json" \
  -d '{"id":"test-realm","auth_params":{"jwt_params":null,"username_password_params":{"allow_expired_passwords":true}},"session_max_age_seconds":28800,"session_max_stale_age_seconds":3600}'

# Create non-admin user 'testuser' — password is sent as PLAINTEXT bytes; the server hashes it
PW=$(python3 -c "import json;print(json.dumps(list(b'testpass123')))")
curl -sk --resolve auth.repro.local:9080:127.0.0.1 -H "Cookie: $ADMIN_COOKIE" \
  -X POST "http://auth.repro.local:9080/realms/test-realm/userpass" -H "Content-Type: application/json" \
  -d "{\"realm\":\"test-realm\",\"username\":\"testuser\",\"password\":$PW,\"change_password\":false,\"roles\":[]}"
```

> **Important:** send the **plaintext** password bytes. The server hashes with
> Argon2 on storage. Sending a pre-computed hash would be double-hashed and login
> would fail.

### 5.4 Non-admin login → capture cookie

```bash
USER_COOKIE=$(curl -sk -D - --resolve auth.repro.local:9080:127.0.0.1 \
  -X POST "http://auth.repro.local:9080/login?realm=test-realm" -u "testuser:testpass123" \
  -H "Content-Type: application/json" -d '{}' \
  | grep -i '^set-cookie:' | sed 's/^set-cookie: //I' | cut -d';' -f1 | tr -d '\r')
echo "USER_COOKIE=$USER_COOKIE"
```

### 5.5 Forward-auth allows the authenticated request → 200

```bash
curl -s -o /dev/null -w "with-cookie -> %{http_code}\n" \
  --resolve protected.repro.local:9080:127.0.0.1 \
  -H "Cookie: $USER_COOKIE" \
  http://protected.repro.local:9080/
# expect: with-cookie -> 200
```

Seeing `no-cookie -> 401` followed by `with-cookie -> 200` confirms the
`forward-auth` gate is working: APISIX calls auth-server's `/whoami`, relays its
status, and only forwards to the protected upstream when the session is valid.

---

## 6. Inspect / troubleshoot

```bash
docker compose ps                       # container status
docker compose logs auth-server | tail  # auth-server logs
docker compose logs apisix | grep -i upstream_status | tail   # gateway relay proof
```

---

## 7. Tear down

```bash
docker compose down -v
rm -rf tls jwt .env
```

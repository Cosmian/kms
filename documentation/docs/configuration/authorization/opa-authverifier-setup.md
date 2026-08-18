# OPA + Authentication Verifier Setup

Step-by-step configuration guide for running Mode 2 (exclusive OPA) or
Mode 3 (enforcing OPA + native KMS) with an OPA sidecar and the Cosmian
Authentication Verifier as the JWT issuer.

---

## Step 1 — Authentication Verifier: issuing JWTs with role claims

The KMS reads three JWT claims for RBAC:

| Claim | RFC | Content | Example |
|---|---|---|---|
| `sub` | RFC 7519 §4.1.2 | User identity (forwarded to OPA as `input.user`) | `"alice@acme.com"` |
| `roles` | RFC 9068 §2.2.3.1 | Array of role strings | `["CryptoOfficer"]` |
| `as_rid` | private (RFC 7519 §4.3) | Realm ID = tenant domain (forwarded as `input.user_domain`) | `"acme.com"` |

> The KMS accepts both **`as_rid`** (Cosmian Authentication Verifier) and **`as_domain`**
> (legacy alias) for the domain claim. Third-party IdPs should map their tenant field to
> `as_rid`.

### Cosmian Authentication Verifier (recommended)

The Cosmian Authentication Verifier is the reference IdP for this feature. It supports
realms (= domains) and per-user role assignment natively, and emits the `roles` and
`as_rid` claims required by the KMS OPA policy.

→ **[Authentication Verifier installation and configuration](https://docs.cosmian.com/authentication_verifier/installation.html)**

Once the Authentication Verifier is running, provision a realm and users:

```bash
CA=/path/to/auth-verifier/certs/auth.ca.pem

# 1 — Login as super-admin (stores session cookie)
curl -s --cacert $CA -c /tmp/auth-admin.txt \
  -X POST "https://localhost:8443/login?realm=_" \
  -u "admin:change_me" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}'

# 2 — Create realm "acme.com"
curl -s --cacert $CA -b /tmp/auth-admin.txt \
  -X POST "https://localhost:8443/admins/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acme.com",
    "auth_params": {
      "username_password_params": {"allow_expired_passwords": false}
    },
    "session_max_age_seconds": 3600,
    "session_max_stale_age_seconds": 7200
  }'

# 3 — Create a user with role CryptoOfficer
#     Passwords must be hashed: Argon2id(password, salt=base64(SHA-256(username)))
HASH=$(python3 - << 'EOF'
import hashlib, base64
from argon2 import PasswordHasher
username, password = "alice", "alice-pass"
salt = base64.b64encode(hashlib.sha256(username.encode()).digest()).rstrip(b"=")
ph = PasswordHasher(time_cost=3, memory_cost=4096, parallelism=1, hash_len=32)
print(ph.hash(password, salt=base64.b64decode(salt + b"==")))
EOF
)

curl -s --cacert $CA -b /tmp/auth-admin.txt \
  -X POST "https://localhost:8443/realms/acme.com/userpass" \
  -H "Content-Type: application/json" \
  -d "{
    \"realm\": \"acme.com\",
    \"username\": \"alice\",
    \"password\": \"$HASH\",
    \"change_password\": false,
    \"roles\": [\"CryptoOfficer\"],
    \"domain\": \"acme.com\"
  }"
```

#### Obtain a JWT

```bash
JWT=$(curl -s --cacert $CA -D - \
  -X POST "https://localhost:8443/login?realm=acme.com" \
  -u "alice:alice-pass" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}' \
  | grep -i "set-cookie: _ea_=" \
  | sed 's/.*_ea_=\([^;]*\).*/\1/' | tr -d '\r')

# Inspect claims (optional)
echo $JWT | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

#### Configure KMS to trust the Authentication Verifier

```toml
# kms.toml
[idp_auth]
# Format: "issuer,jwks_uri"
jwt_auth_provider = ["cosmian-auth-test,https://localhost:8443/public/jwks"]

[opa]
opa_url  = "http://localhost:8181"
opa_mode = "enforcing"
```

| Endpoint | Method | Description |
|---|---|---|
| `GET /public/jwks` | — | JWKS endpoint (KMS fetches this to validate JWTs) |
| `GET /public/roles` | — | List of configured role names |
| `POST /admins/realms` | JSON | Create a realm |
| `POST /realms/<realm>/userpass` | JSON | Create a user with roles + domain |
| `DELETE /realms/<realm>/userpass/<username>` | — | Delete a user |

---

## Step 2 — OPA server: deploy and load the Rego policy

### Docker Compose (recommended for production)

```yaml
# docker-compose.yml
services:
  opa:
    image: openpolicyagent/opa:edge-static-debug
    ports:
      - "8181:8181"
    volumes:
      - ./test_data/opa/kms.rego:/policies/kms.rego:ro
    command:
      - run
      - --server
      - --log-level=info
      - --addr=0.0.0.0:8181
      - /policies/kms.rego
```

```bash
docker compose up -d opa
```

### Standalone Docker

```bash
docker run -d --name opa \
  -p 8181:8181 \
  -v "$(pwd)/test_data/opa/kms.rego:/policies/kms.rego:ro" \
  openpolicyagent/opa:edge-static-debug \
  run --server --log-level=info --addr=0.0.0.0:8181 /policies/kms.rego
```

### Verify OPA is ready

```bash
curl http://localhost:8181/health

# Test a CryptoOfficer create request — expect {"result":true}
curl -s -X POST http://localhost:8181/v1/data/kms/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": "alice@acme.com",
      "user_domain": "acme.com",
      "roles": ["CryptoOfficer"],
      "operation": "create",
      "object_uid": "*",
      "object_domain": "acme.com",
      "is_owner": false
    }
  }'
```

---

## Step 3 — KMS server: wire JWT auth and OPA

### kms.toml

```toml
[http]
hostname = "0.0.0.0"
port     = 9998

[db]
database_type = "sqlite"
sqlite_path   = "/var/lib/kms/data"

[idp_auth]
jwt_auth_provider = ["cosmian-auth-test,https://localhost:8443/public/jwks"]

[opa]
opa_url  = "http://localhost:8181"
opa_mode = "enforcing"
```

### Environment variables

| Variable | Example | Description |
|---|---|---|
| `KMS_JWT_AUTH_PROVIDER` | `https://auth.acme.com` | IdP issuer (+ optional JWKS URI and audiences) |
| `KMS_OPA_URL` | `http://localhost:8181` | OPA base URL |
| `KMS_OPA_MODE` | `enforcing` | `exclusive` or `enforcing` |

### Starting the KMS server

```bash
RUST_LOG="cosmian_kms_server=debug" \
cosmian_kms \
  --database-type sqlite \
  --sqlite-path /tmp/kms-data \
  --jwt-auth-provider "cosmian-auth-test,https://auth.acme.com/public/jwks" \
  --opa-url http://localhost:8181 \
  --opa-mode enforcing
```

---

## Step 4 — Obtain a JWT and call the KMS

### With the Cosmian Authentication Verifier

```bash
CA=/path/to/auth-verifier/certs/auth.ca.pem

JWT=$(curl -s --cacert $CA -D - \
  -X POST "https://auth.acme.com/login?realm=acme.com" \
  -u "alice:alice-pass" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}' \
  | grep -i "set-cookie: _ea_=" \
  | sed 's/.*_ea_=\([^;]*\).*/\1/' | tr -d '\r')

cat > /tmp/ckms-alice.toml << EOF
[http_config]
server_url   = "http://kms.acme.com:9998"
access_token = "${JWT}"
EOF

ckms -c /tmp/ckms-alice.toml sym keys create -t test-key
```

### Via PKCE / OAuth2 browser flow

Standard OIDC providers that support OAuth2 PKCE can authenticate via a browser flow.
Configure `ckms.toml` with the provider's `authorize_url` and `token_url`, then
use `ckms login`:

```toml
# ckms.toml
[http_config]
server_url = "http://kms.acme.com:9998"

[http_config.oauth2_conf]
client_id     = "ckms-client"
client_secret = ""
authorize_url = "https://auth.acme.com/oauth2/authorize"
token_url     = "https://auth.acme.com/oauth2/token"
scopes        = ["openid", "email"]
```

```bash
ckms -c ckms.toml login    # opens browser → saves token
ckms -c ckms.toml sym keys create
ckms -c ckms.toml logout
```

---

## Debugging access denials

### Query the OPA reason endpoint

```bash
curl -s -X POST http://localhost:8181/v1/data/kms/reasons \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": "alice@acme.com",
      "user_domain": "acme.com",
      "roles": ["CryptoOfficer"],
      "operation": "destroy",
      "object_uid": "key-123",
      "object_domain": "acme.com",
      "is_owner": false
    }
  }'
# {"result":["crypto_officer"]}  → allowed
# {"result":["denied"]}          → no rule matched
```

### Enable trace logging on the KMS

```bash
RUST_LOG="cosmian_kms_server=trace" cosmian_kms ...
```

Look for `ensure_auth` (JWT parsing), `retrieve_object_utils` (OPA input), and
`core::opa::client` (HTTP round-trip timing).

---

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 Unauthorized` | JWT missing or signature invalid | Check `--jwt-auth-provider` issuer and JWKS URI |
| `403` — OPA deny | Role not in JWT or cross-domain | Check `roles` claim; verify `as_rid` matches `object_domain` |
| `403` — OPA unreachable | OPA not running or wrong port | Check `KMS_OPA_URL`; run `curl http://localhost:8181/health` |
| `403` — Native KMS deny | Mode 3: no DB grant | Add grant with `ckms access-rights grant`, or switch to Mode 2 |
| Empty `roles: []` in OPA | mTLS or API-token auth | Roles only come from JWT |
| `roles` not in JWT | Authentication Verifier not configured | Check that the realm emits `roles` and `as_rid` claims — see the [Authentication Verifier docs](https://docs.cosmian.com/authentication_verifier/installation.html) |

---

## See also

- [Authorization overview](index.md)
- [Mode 3 — Enforcing (OPA + KMS)](mode3.md)
- [Authentication methods](../authentication.md)
- [Authentication Verifier documentation](https://docs.cosmian.com/authentication_verifier/installation.html)
- Rego policy source: `test_data/opa/kms.rego`

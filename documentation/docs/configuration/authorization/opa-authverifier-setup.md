# OPA + Authentication Verifier Setup

Step-by-step configuration guide for running Mode 2 (exclusive OPA) or
Mode 3 (enforcing OPA, with the native KMS permission system kept for Crypto Officers and HSM-backed objects)
with an OPA sidecar and the Cosmian Authentication Verifier as the JWT issuer.

---

## Step 1 — Authentication Verifier: issuing JWTs with role claims

The KMS reads these JWT claims for RBAC:

| Claim | RFC | Content | Example |
|---|---|---|---|
| `email` | OIDC standard claim | User identity of a third-party IdP token, forwarded to OPA as `input.user`. Used when present and not blank. Authentication Verifier tokens carry none | `"alice@acme.com"` |
| `sub` | RFC 7519 §4.1.2 | Identity of an Authentication Verifier token; for a third-party token, the fallback when `email` is absent or blank. A third-party token with neither is rejected | `"alice"` |
| `roles` | RFC 9068 §2.2.3.1 | Array of role strings | `["CryptoOfficer"]` |
| `as_rid` | private (RFC 7519 §4.3) | Realm ID = tenant domain (forwarded as `input.user_domain`) | `"acme.com"` |

!!! note "Domain claim"
    The KMS reads the domain from **`as_rid`** (Cosmian Authentication Verifier) and accepts **`as_domain`** as a legacy alias. A bare `domain` claim is **not** read: a token that only carries `domain` has no domain, and every domain-scoped role denies it. Third-party IdPs must map their tenant field to `as_rid`.

!!! warning "The identity is not namespaced"
    The identity is the `email` (or `sub`) value alone: the KMS does not add the issuer or the realm to it. Two realms, or two issuers listed in `jwt_auth_provider`, that issue the same value are the same user for the KMS (same ownership, same native grants). Only trust issuers whose identity namespace you control, and do not let users choose their own `email`.

### Cosmian Authentication Verifier (recommended)

The Cosmian Authentication Verifier is the reference IdP for this feature. It supports
realms (= domains) and per-user role assignment natively, and emits the `roles` and
`as_rid` claims required by the KMS OPA policy.

→ **[Authentication Verifier installation and configuration](https://docs.cosmian.com/authentication_verifier/installation.html)**

Once the Authentication Verifier is running, provision a realm and users. Export the administrator password and the user password first (`AUTH_ADMIN_PASSWORD`, `ALICE_PASSWORD`): the snippets read them from the environment and need `curl` and `jq`.

```bash
CA=/path/to/auth-verifier/certs/auth.ca.pem
COOKIE_JAR="$(mktemp)"
trap 'rm -f -- "$COOKIE_JAR"' EXIT

# 1 — Login as super-admin (stores session cookie)
curl -s --cacert "$CA" -c "$COOKIE_JAR" \
  -X POST "https://localhost:8443/login?realm=_" \
  -u "admin:${AUTH_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}'

# 2 — Create realm "acme.com"
curl -s --cacert "$CA" -b "$COOKIE_JAR" \
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

# 3 — Create a user with role CryptoOfficer (the server hashes the password)
#     jq reads the password from the environment, so it never appears in a process argument list
jq -n '{
    realm: "acme.com",
    username: "alice",
    password_input: {plaintext: env.ALICE_PASSWORD},
    change_password: false,
    roles: ["CryptoOfficer"]
  }' |
  curl -s --cacert "$CA" -b "$COOKIE_JAR" \
    -X POST "https://localhost:8443/realms/acme.com/userpass" \
    -H "Content-Type: application/json" \
    --data-binary @-
```

The realm ID is the domain of its users: the Authentication Verifier puts it in the `as_rid` claim of every token, and a user has no other domain setting. The role names must be the ones configured on the Authentication Verifier (`GET /public/roles` lists them) and must match the roles of the Rego policy: `SuperAdmin`, `DomainAdmin`, `CryptoOfficer`, `Auditor` and `User`.

#### Obtain a JWT

```bash
JWT=$(curl -s --cacert "$CA" -D - \
  -X POST "https://localhost:8443/login?realm=acme.com" \
  -u "alice:${ALICE_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}' \
  | grep -i "set-cookie: _ea_=" \
  | sed 's/.*_ea_=\([^;]*\).*/\1/' | tr -d '\r')

# Inspect claims (optional)
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

#### Configure KMS to trust the Authentication Verifier

```toml
# kms.toml
[auth_verifier]
# The KMS gets the signing keys from <auth_verifier_url>/.well-known/jwks.json and checks that
# the session of every token is still live with GET <auth_verifier_url>/whoami.
auth_verifier_url = "https://localhost:8443"

[opa]
opa_url  = "http://127.0.0.1:8181"
opa_mode = "enforcing"
```

The tokens of the Authentication Verifier carry no `iss`, `aud` or `email` claim and no `kid` header: the identity of the user is the `sub` claim. They are validated by the `[auth_verifier]` table, not by `jwt_auth_provider`, which is meant for third-party OpenID Connect providers and answers HTTP `401` to a token without `kid` header or `iss` claim.

`[auth_verifier]` is set in the configuration file only: it has no command-line flag and no environment variable. Add `auth_verifier_realm = ["acme.com"]` to enable the login form of the Web UI; bearer-token validation does not need it.

The KMS verifies the TLS certificate of the Authentication Verifier when it fetches the signing keys and when it calls `whoami`, so the certificate must chain to a CA that the KMS trusts. `auth_verifier_accept_invalid_certs = true` turns this check off: use it for a throw-away test only. While the KMS cannot reach `auth_verifier_url`, it refuses every Authentication Verifier token, and a session that was revoked on the Authentication Verifier is refused within 30 seconds: see the last note of the SAML section of [the KMS User Interface page](../ui.md).

| Endpoint | Method | Description |
|---|---|---|
| `GET /.well-known/jwks.json` | — | JWKS endpoint (KMS fetches this to validate the signature of the tokens) |
| `GET /public/roles` | — | List of configured role names |
| `POST /admins/realms` | JSON | Create a realm |
| `POST /realms/<realm>/userpass` | JSON | Create a user with roles (the realm ID is its domain) |
| `DELETE /realms/<realm>/userpass/<username>` | — | Delete a user |

---

## Step 2 — OPA server: deploy and load the Rego policy

### Docker Compose (recommended)

```yaml
# docker-compose.yml
services:
  opa:
    # Pinned by digest: never run the authorization engine from a mutable tag such as `edge`.
    image: openpolicyagent/opa:1.22.0-static-debug@sha256:b5dde1457f91dd775a72b7865e6b3d0deb537ddf474726dc356ecb01f970ac4d
    ports:
      # Loopback only: OPA has no authentication and the KMS has no OPA-specific credentials to offer.
      - "127.0.0.1:8181:8181"
    volumes:
      - ./test_data/opa/kms.rego:/policies/kms.rego:ro
    command:
      - run
      - --server
      - --log-level=info
      # Listens on all interfaces of the container so that the published port works.
      - --addr=0.0.0.0:8181
      - /policies/kms.rego
```

```bash
docker compose up -d opa
```

### Standalone Docker

```bash
docker run -d --name opa \
  -p 127.0.0.1:8181:8181 \
  -v "$(pwd)/test_data/opa/kms.rego:/policies/kms.rego:ro" \
  openpolicyagent/opa:1.22.0-static-debug@sha256:b5dde1457f91dd775a72b7865e6b3d0deb537ddf474726dc356ecb01f970ac4d \
  run --server --log-level=info --addr=0.0.0.0:8181 /policies/kms.rego
```

!!! warning "OPA is unauthenticated"
    Anyone who can reach the OPA port can read the policy and query decisions, and the KMS trusts whatever answers on the configured `opa_url`. Keep the port on the loopback interface or a private network shared only with the KMS, and see [Harden a production OPA](mode2.md#deploying-the-opa-sidecar) before exposing it any further.

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

# Bearer tokens travel in the Authorization header: always serve the KMS over TLS.
[tls]
tls_cert_file = "path/to/server.crt"
tls_key_file  = "path/to/server.key"

[db]
database_type = "sqlite"
sqlite_path   = "/var/lib/kms/data"

[auth_verifier]
auth_verifier_url = "https://localhost:8443"

[opa]
opa_url  = "http://127.0.0.1:8181"
opa_mode = "enforcing"
```

To trust a third-party OpenID Connect provider instead of the Authentication Verifier, set `jwt_auth_provider` in the `[idp_auth]` table, in the form `"issuer,jwks_uri[,audience...]"`: the [Keycloak demo](rbac-keycloak-opa-demo.md#how-a-token-becomes-an-opa-decision) shows a complete example. The KMS then requires the `exp` and `iss` claims, and the `aud` claim when you list an audience. List the audience whenever the provider puts an `aud` claim in its tokens: without one, the KMS accepts any token of this issuer, whatever service it was issued for. The provider must also emit the `roles` and `as_rid` claims described at the top of this page.

### Environment variables

| Variable | Example | Description |
|---|---|---|
| `KMS_JWT_AUTH_PROVIDER` | `https://auth.acme.com` | Third-party OpenID Connect provider (issuer, optional JWKS URI and audiences). Not used for the Authentication Verifier |
| `KMS_OPA_URL` | `http://127.0.0.1:8181` | OPA base URL. Setting it requires `KMS_OPA_MODE` to be `exclusive` or `enforcing`: the server refuses to start with a URL and the default mode `disabled` |
| `KMS_OPA_MODE` | `enforcing` | `exclusive` or `enforcing` (default `disabled`) |

The `[auth_verifier]` table has no environment variable and no command-line flag: it is set in `kms.toml` only.

### Starting the KMS server

```bash
RUST_LOG="cosmian_kms_server=info,audit=warn" cosmian_kms -c kms.toml
```

`audit=warn` keeps the `OPA_DENIED` lines, which the KMS writes under the `audit` log target: see [Debugging access denials](#debugging-access-denials).

---

## Step 4 — Obtain a JWT and call the KMS

### With the Cosmian Authentication Verifier

```bash
CA=/path/to/auth-verifier/certs/auth.ca.pem

JWT=$(curl -s --cacert "$CA" -D - \
  -X POST "https://auth.acme.com/login?realm=acme.com" \
  -u "alice:${ALICE_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem":null,"totp_code":null}' \
  | grep -i "set-cookie: _ea_=" \
  | sed 's/.*_ea_=\([^;]*\).*/\1/' | tr -d '\r')

# mktemp creates the file readable by its owner only: it holds a bearer token
CKMS_CONF="$(mktemp)"
trap 'rm -f -- "$CKMS_CONF"' EXIT
cat > "$CKMS_CONF" << EOF
[http_config]
server_url   = "https://kms.acme.com:9998"
access_token = "${JWT}"
EOF

ckms -c "$CKMS_CONF" sym keys create -t test-key
```

The client must trust the KMS certificate: see [client authentication](../../kms_clients/authentication.md) to pin a private CA certificate with `verified_cert`.

### Via PKCE / OAuth2 browser flow

Standard OIDC providers that support OAuth2 PKCE can authenticate via a browser flow.
Configure `ckms.toml` with the provider's `authorize_url` and `token_url`, then
use `ckms login`:

```toml
# ckms.toml
[http_config]
server_url = "https://kms.acme.com:9998"

# PKCE: the client is public, so `client_secret` is the empty string. Never put the secret of a
# confidential client in a configuration file that is shared or committed.
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

### Read the KMS denial log

Every denial by OPA is logged at `WARN` level as a line containing `OPA_DENIED`, with the user, roles, user domain, operation, object identifier, object domain and mode. The values come from the token and the request, so they are logged escaped. An unreachable OPA is a denial too: the same line is logged, and the OPA client logs the transport error just before it.

The line is written under the `audit` log target. When you set `RUST_LOG`, keep that target in the filter, for example `RUST_LOG="cosmian_kms_server=info,audit=warn"`: a filter that names only `cosmian_kms_server` drops it.

### Query the OPA reason endpoint

```bash
curl -s -X POST http://127.0.0.1:8181/v1/data/kms/reasons \
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
RUST_LOG="cosmian_kms_server=trace,audit=warn" cosmian_kms ...
```

Look for `ensure_auth` (JWT parsing), `retrieve_object_utils` (OPA input), and
`core::opa::client` (HTTP round-trip timing).

---

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| The server refuses to start: "`--opa-url` is set but `--opa-mode` is `disabled`" | An OPA URL without a mode: OPA would never be consulted | Set `--opa-mode` to `exclusive` or `enforcing`, or remove `--opa-url` |
| HTTP `401 Unauthorized` | Token missing, expired or with an invalid signature. With an Authentication Verifier: the session has ended, the KMS cannot reach `auth_verifier_url`, or it does not trust the certificate of the Authentication Verifier. With `jwt_auth_provider`: the `iss` or `aud` claim does not match the entry, the token has no `kid` header, or it has neither a usable `email` nor a `sub` | Check `auth_verifier_url`, or the issuer, JWKS URI and audience of the `jwt_auth_provider` entry. Authentication Verifier tokens do not work with `jwt_auth_provider`: they carry no `iss` |
| A KMIP `Object_Not_Found` error on an existing object: HTTP `422` on the single-operation JSON route `/kmip/2_1`, an `OperationFailed` batch item in a KMIP message | OPA denied the operation, or OPA is unreachable (fail-closed). A denial looks the same as a missing object | Find the `OPA_DENIED` log line; check the `roles` claim and that `as_rid` equals the object domain |
| `Create` fails with "User does not have create access-right." | OPA denied `create` for the role or the domain of the caller, or OPA is unreachable | Same as above |
| Every request is denied | OPA not running or wrong `opa_url` | Check `KMS_OPA_URL`; run `curl http://127.0.0.1:8181/health` |
| A domain-scoped role is denied although the role and the domain look right | The object has an empty domain (it was not created by the `Create` operation, or the database is Redis-Findex), or the token has no `as_rid` claim | Only the owner and the `SuperAdmin`s can reach an object without a domain; see [the domain model](index.md#domain-model) |
| Native KMS deny | Mode 3, HSM-backed object (OPA allowed) or native Crypto Officer candidate: no ownership, HSM-admin right or grant | Add a grant with `ckms access-rights grant` |
| Empty `roles: []` in OPA | mTLS or API-token auth | Roles only come from JWT |
| `roles` not in JWT | Authentication Verifier not configured | Check that the realm emits `roles` and `as_rid` claims — see the [Authentication Verifier docs](https://docs.cosmian.com/authentication_verifier/installation.html) |

---

## See also

- [Authorization overview](index.md)
- [Mode 3 — Enforcing (OPA + KMS)](mode3.md)
- [Authentication methods](../authentication.md)
- [Authentication Verifier documentation](https://docs.cosmian.com/authentication_verifier/installation.html)
- Rego policy source: `test_data/opa/kms.rego`

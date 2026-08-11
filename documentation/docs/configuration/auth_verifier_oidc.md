# On-Premise OIDC with auth-verifier

The Cosmian `auth-verifier` server includes a full **OpenID Connect Provider (OP)**,
which allows KMS to use an on-premise identity provider without any cloud dependency
(no Google, Azure, Auth0, or Keycloak required).

## How it works

```text
Browser / ckms             auth-verifier (OIDC OP)               KMS server
     │                    ┌────────────────────┐                ┌──────────┐
     │  /oidc/authorize ─►│ authorization_endpoint              │          │
     │  /oidc/token ─────►│ token_endpoint     │  Bearer token  │AuthVerif.│
     │  Bearer: at+jwt ───┼────────────────────┼───────────────►│middleware│
     │                    │ /oidc/jwks ─────────┼───────────────►│JwksMgr  │
     └────────────────────┴────────────────────┘                └──────────┘
```

The KMS accepts two token types from the auth-verifier:

| Token type | `kid` header | Key lookup |
|---|---|---|
| OIDC `at+jwt` access token | ✅ Present | Fast: `JwksManager::find(kid)` |
| Legacy session JWT | ❌ Absent | Fallback: try all keys |

Both are validated against the **combined JWKS** at `/oidc/jwks` (which contains both
the dedicated OIDC signing key and the session key).

## Prerequisites

### 1. Running auth-verifier

See [the auth-verifier documentation](https://github.com/Cosmian/authentication) for
installation and setup.  The quickest way to get started is the bundled dev config:

```sh
cd authentication
./target/debug/auth_verifier server/auth_verifier.dev.toml
```

This starts the server on `https://localhost:8443` with a pre-seeded realm `_` and
admin credentials `admin` / `change_me`.

### 2. Register a realm (if not using the default `_`)

```sh
curl -X POST https://localhost:8443/admin/realms \
  -H "Authorization: Bearer <super-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"realm_id": "kms"}'
```

### 3. Register an OIDC client

```sh
curl -X POST https://localhost:8443/admin/realms/kms/clients \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "KMS",
    "redirect_uris": ["https://kms.example.com/ui/oidc/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"]
  }'
```

The response includes a `client_id` and `client_secret` (shown only once).

## KMS configuration

A single `[auth_verifier]` section is all that is needed.  The KMS automatically
derives the Web UI OIDC configuration from it — no separate `[ui_config.ui_oidc_auth]`
section is required.

```toml
[auth_verifier]
auth_verifier_url                = "https://auth.example.com"
auth_verifier_realm              = "kms"
auth_verifier_oidc_client_id     = "kms-client"
auth_verifier_oidc_client_secret = "s3cr3t"
# auth_verifier_oidc_scopes      = "openid profile email"   # default
# auth_verifier_jwks_uri         = "…"                      # override if needed

[ui_config]
ui_session_salt = "<openssl rand -hex 32>"
```

### Configuration reference

| Field | Env var | Default | Description |
|---|---|---|---|
| `auth_verifier_url` | `KMS_AUTH_VERIFIER_URL` | — | Base URL of the auth-verifier |
| `auth_verifier_realm` | `KMS_AUTH_VERIFIER_REALM` | — | Realm for password login form |
| `auth_verifier_jwks_uri` | `KMS_AUTH_VERIFIER_JWKS_URI` | `{url}/oidc/jwks` | JWKS endpoint override |
| `auth_verifier_oidc_client_id` | `KMS_AUTH_VERIFIER_OIDC_CLIENT_ID` | — | OIDC client ID |
| `auth_verifier_oidc_client_secret` | `KMS_AUTH_VERIFIER_OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `auth_verifier_oidc_scopes` | `KMS_AUTH_VERIFIER_OIDC_SCOPES` | `openid profile email` | Space-separated scopes |
| `auth_verifier_accept_invalid_certs` | `KMS_AUTH_VERIFIER_ACCEPT_INVALID_CERTS` | `false` | Skip TLS cert check (dev only) |

## CLI usage: `ckms login cosmian --use-oidc`

The `--use-oidc` flag triggers the standard OIDC Authorization Code + PKCE flow
(same mechanism as `ckms login oauth`, but auto-configured from `cosmian_conf`):

```sh
ckms login cosmian --use-oidc
# Opens a browser window → redirects to auth-verifier /oidc/authorize
# → after login, the access token is stored in the ckms config file
```

Configure `cosmian_conf` in your `kms.toml`:

```toml
[http_config.cosmian_conf]
server_url  = "https://auth.example.com"
realm       = "kms"
client_id   = "kms-client"
client_secret = "s3cr3t"   # omit for public/PKCE-only clients
```

Without `--use-oidc`, the original HTTP Basic credential flow is still available:

```sh
ckms login cosmian --username alice --password s3cr3t
```

## Web UI usage

When `auth_verifier_oidc_client_id` is set, the Web UI login page shows an
**"OIDC Login"** button in addition to the password form.  Clicking it starts the
Authorization Code + PKCE flow; the resulting access token is validated server-side
and never reaches the browser.

After successful login, `GET /ui/whoami` returns `{ "user_id": "<sub>" }`.

## Security notes

- The combined JWKS (`/oidc/jwks`) contains both the OIDC signing key and the session
  key.  Always use HTTPS for the auth-verifier; set
  `auth_verifier_accept_invalid_certs = false` in production.
- OIDC `at+jwt` tokens use a **dedicated signing key** (`kid` header present) distinct
  from the session key.  This prevents cross-type token substitution.
- Set `auth_verifier_accept_invalid_certs = true` only in development or testing.

## See also

- [Authentication overview](authentication.md)
- [PKCE Authentication](pkce_authentication.md)
- [auth-verifier repository](https://github.com/Cosmian/authentication)

---

## Option D: Standard `[idp_auth]` only (no BFF login form)

For deployments that only need **bearer-token validation** (M2M / service accounts)
and do not require the Web UI password form, the auth-verifier OIDC Provider can be
configured via the **standard `[idp_auth] jwt_auth_provider`** mechanism — no
`[auth_verifier]` section needed.

### What this option provides

| Feature | `[auth_verifier]` options | Option D (`[idp_auth]`) |
|---------|--------------------------|-------------------------|
| OIDC `at+jwt` bearer-token validation | ✓ | ✓ |
| Web UI OIDC login button | ✓ (via `[ui_config.ui_oidc_auth]`) | ✓ (via `[ui_config.ui_oidc_auth]`) |
| Web UI password-form login | ✓ (POST `/ui/login_as`) | ✗ |
| Legacy session JWTs (no `kid`) | ✓ | ✗ |
| Username derived from `sub` claim | ✓ | ✓ (falls back when `email` absent) |

### Minimal config

```toml
[idp_auth]
# Format: "ISSUER_URL,JWKS_URI[,AUDIENCE...]"
# The auth-verifier OIDC JWKS is at /oidc/jwks.
jwt_auth_provider = [
  "https://auth.example.com,https://auth.example.com/oidc/jwks",
]

# For dev/test with a self-signed certificate on the auth-verifier only.
# Always false in production.
# idp_auth_accept_invalid_certs = true

[ui_config.ui_oidc_auth]
ui_oidc_issuer_url    = "https://auth.example.com"
ui_oidc_client_id     = "<CLIENT_ID>"
ui_oidc_client_secret = "<CLIENT_SECRET>"
```

See `test_data/configs/server/idp_auth_verifier_oidc.toml` for a full working example.

### Token requirements

The auth-verifier OIDC `at+jwt` token must carry:

- `kid` header — identifies the signing key in the JWKS
- `iss` claim — must match the issuer URL in `jwt_auth_provider`
- `sub` claim — used as the KMS username when `email` is absent

The KMS JWT middleware uses `email` when present; otherwise falls back to `sub`.

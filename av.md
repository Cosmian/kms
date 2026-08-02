# KMS Auth-Verifier: ckms & WebUI Authentication — Security & Functionality Review

## Problem Statement

Determine whether `ckms` (CLI) and the KMS Web UI are both able to authenticate to the
KMS server when authentication is delegated to the **auth-verifier** (the `authentication`
server in `Cosmian/authentication`).

---

## What is the "Auth-Verifier"?

The **auth-verifier** (`Cosmian/authentication`) is a standalone authentication server
that offers two interfaces the KMS can delegate to:

| Interface | Endpoint | Used By |
|-----------|----------|---------|
| **Vault-compatible token API** | `GET /auth/token/lookup-self` (X-Vault-Token) | SPIRE workloads / machine-to-machine |
| **JWKS endpoint** | `GET /.well-known/jwks.json` | KMS validates Cosmian JWTs issued by auth-verifier |
| **Login endpoint** | `POST /login?realm=kms` | ckms CLI (`ckms login cosmian`) + WebUI login form |

The KMS delegates authentication to the auth-verifier in two distinct modes:

### Mode A — Cosmian JWT / JWKS delegation

1. Client authenticates directly to auth-verifier (`POST /login`) → receives a JWT.
2. Client sends `Authorization: Bearer <JWT>` to KMS.
3. KMS validates the JWT signature against auth-verifier's JWKS (fetched at startup/cached).
4. No real-time call to auth-verifier on every request.

### Mode B — SPIRE/Vault token delegation (real-time)

1. Client obtains a Vault-compatible token from auth-verifier (out-of-band).
2. Client sends `X-Vault-Token: <token>` to KMS.
3. KMS calls `GET {auth_verifier}/auth/token/lookup-self` (caches 30s TTL).
4. Maps `entity_id` → KMS username.

---

## ckms CLI — Auth-Verifier Support

### ✅ Mode A (Cosmian JWT) — SUPPORTED

- `ckms login cosmian --username … --password …` (optionally interactive TOTP).
- Calls auth-verifier `POST /login?realm=kms` with Basic credentials.
- Stores JWT in `ckms.toml` as `access_token` (**plaintext on disk**).
- All subsequent KMS requests send `Authorization: Bearer <JWT>`.
- KMS `CosmianAuthServer` middleware validates JWT via JWKS.

### ❌ Mode B (SPIRE/Vault token) — NOT SUPPORTED

- No CLI flag or config field for `X-Vault-Token`.
- No `ckms login spire` or similar subcommand.
- The SPIRE token flow is designed for machine workloads (Vault plugin / SPIRE agent), not user-facing CLI.

### ⚠️ Gaps

1. **No token refresh**: stored JWT is static; user must re-run `ckms login cosmian` when it expires.
   The OAuth flow also discards `refresh_token` (`#[serde(skip)]` in `OAuthResponse`).
2. **Token stored in plaintext** in `ckms.toml` (file-system security only).
   Confirmed: `commands.rs:201-204` persists config (including `access_token`) to disk.
   The `println!("saved in the KMS configuration (in memory)")` message is **misleading**.
3. **`TODO: remove accept_invalid_certs`** in `login.rs` (2 occurrences, lines 438 and 460).
4. **Password passed as CLI argument** (`--password`/`-p`): visible in `ps`, shell history,
   `/proc/*/cmdline`. No interactive password prompt fallback.

---

## Web UI — Auth-Verifier Support

### ✅ Mode A (Cosmian JWT via session) — SUPPORTED

- `App.tsx` detects `authMethod === "COSMIAN"` via `GET /ui/auth_method` and shows username/password form.
- Login form posts to KMS BFF proxy route (`POST /ui/login_as`), which proxies to auth-verifier.
- KMS validates credentials against auth-verifier, validates the returned JWT via JWKS,
  issues an **HTTP-only session cookie** (`auth_session`).
- All subsequent WASM/fetch calls include the session cookie automatically (`credentials: 'include'`).
- `SessionAuth` middleware on KMS side validates the session and maps to `AuthenticatedUser`.

### ❌ Mode B (SPIRE/Vault token) — NOT SUPPORTED

- `X-Vault-Token` header is not injected by the UI in any code path.
- Session-based flow is orthogonal to SPIRE token flow.
- SPIRE/Vault tokens are not intended for browser clients.

### ⚠️ Gaps

1. **`idToken` / JWT removed from AuthContext**: the browser no longer sees the raw JWT; auth is fully session-based. This is correct and more secure, but WASM-based clients outside the KMS web UI origin cannot reuse the session.
2. **No TOTP in OIDC flow**: OIDC path doesn't integrate TOTP.
3. **24h session TTL with no server-side revocation**: a stolen session cookie is valid for 24h.
   `CookieSessionStore` is client-side (encrypted cookie), so there is no way to invalidate
   sessions before TTL expiry.
4. **BFF proxy duplicates auth-verifier response types**: `ui_auth.rs` manually mirrors
   `AuthenticationResult` / `CosmianAuthenticationNextStep` rather than depending on the
   auth-verifier crate. If the auth-verifier adds a new `next_step` variant, the KMS will
   silently treat it as an error.

---

## Comparison Matrix

| Capability | ckms CLI | Web UI |
|---|---|---|
| Cosmian JWT (Mode A) | ✅ `ckms login cosmian` | ✅ Login form → session cookie |
| OIDC/OAuth JWT (Mode A variant) | ✅ `ckms login oauth` | ✅ OAuth redirect flow |
| SPIRE/Vault token (Mode B) | ❌ Not supported | ❌ Not applicable |
| TOTP support | ✅ Interactive prompt | ✅ UI field |
| Token storage security | 🔴 Plaintext in ckms.toml | ✅ HTTP-only session cookie |
| Token refresh | ❌ Manual re-login | ✅ Session expiry managed by server |
| TLS validation on login | ⚠️ Configurable but TODO-marked | ✅ Server-side (KMS→AS, secure by default) |
| TLS validation on OAuth token exchange | 🔴 **Hardcoded disabled** | N/A (server-side) |
| Password input security | 🔴 CLI arg (visible in `ps`) | ✅ Form field |
| Auth-verifier delegation at login | ✅ Direct call to auth-verifier | ✅ Server-side BFF proxy to auth-verifier |
| Auth-verifier validation on each request | ❌ JWKS-only (cached) | ❌ JWKS-only (via session) |

---

## Security Issues Found

### 🔴 P0 — Critical

#### 1. Hardcoded `accept_invalid_certs: true` in OAuth `request_token()`

**File**: `crate/clients/client/src/http_client/login.rs:338`

```rust
// request_token() — OAuth2 token exchange
let client = super::HttpClient::instantiate(&super::HttpClientConfig {
    server_url: login_config.token_url.clone(),
    accept_invalid_certs: true,  // ← HARDCODED, not user-configurable
    ..Default::default()
})
```

This is **worse** than the Cosmian login TODO because:

- The Cosmian login one at least reads from config (`config.http_config.accept_invalid_certs`)
- The OAuth one is **hardcoded to `true`** — TLS certificate validation is unconditionally
  disabled for the token exchange endpoint
- An attacker MITM-ing the OAuth token endpoint can steal the authorization code and PKCE verifier

**Fix**: Respect `config.http_config.accept_invalid_certs` or default to `false`.

#### 2. JWT stored in plaintext in `ckms.toml`

**File**: `crate/clients/ckms/src/commands.rs:201-204`

The JWT is persisted to disk in the TOML config file. Any process with read access to
`ckms.toml` obtains a valid bearer token. File permissions may not be restrictive enough.

**Fix**: Consider OS keychain integration, or at minimum set restrictive file permissions
(`0600`) on the config file when writing tokens.

#### 3. Password passed as CLI argument

**File**: `crate/clients/clap/src/actions/login.rs:51-54`

```rust
Cosmian {
    username: String,
    password: String,  // ← visible in `ps`, shell history, etc.
}
```

The password is a required CLI argument. It appears in:

- Shell history
- `/proc/*/cmdline` on Linux
- Process listings (`ps aux`)

**Fix**: Support interactive password input (e.g., `rpassword` crate) when `--password` is omitted.

### 🟡 P1 — Medium

#### 4. No audience validation on Cosmian JWTs

**File**: `crate/server/src/middlewares/cosmian_auth_server/token.rs:137`

```rust
validation.validate_aud = false;
```

Cosmian JWTs don't validate the `aud` claim. A JWT issued by the auth-verifier for a
*different* relying party would be accepted by the KMS. If the auth-verifier serves multiple
services, token substitution across services is possible.

**Fix**: Add configurable expected audience validation.

#### 5. No issuer validation on Cosmian JWTs

**File**: `crate/server/src/middlewares/cosmian_auth_server/token.rs:134-135`

```rust
// Do not validate issuer — the Cosmian auth server may not set `iss`.
validation.set_issuer::<String>(&[]);
```

If multiple IdPs are in the environment, a JWT from a different issuer (with a valid
signature from a key that happens to be in the JWKS) would be accepted.

**Fix**: Add configurable expected issuer validation.

#### 6. JWKS cache empty → `force_refresh()` on every unauthenticated request (DoS amplifier)

**File**: `crate/server/src/middlewares/cosmian_auth_server/token.rs:117-126`

When the JWKS cache is empty, `force_refresh()` is called synchronously during request
handling. If the auth-verifier is unreachable at startup, every incoming bearer-token
request triggers an outbound HTTPS fetch before failing. An attacker can flood the KMS
with invalid bearer tokens, each causing a blocking network call.

**Fix**: Rate-limit the `force_refresh()` path or return immediately with a cached
"unavailable" state after the first failed attempt.

#### 7. OAuth `refresh_token` discarded

**File**: `crate/clients/client/src/http_client/login.rs:281-283`

```rust
pub struct OAuthResponse {
    #[serde(skip)]
    pub refresh_token: Option<String>,  // ← parsed but never used
}
```

The IdP may return a refresh token, but it is explicitly skipped and never stored.
Combined with no refresh logic, OAuth sessions also require manual re-login on expiry.

### 🟢 P2 — Low

#### 8. 24h session TTL with no server-side revocation

**File**: `crate/server/src/start_kms_server.rs:1036-1038`

```rust
.session_lifecycle(
    PersistentSession::default().session_ttl(Duration::hours(24)),
)
```

A stolen session cookie is valid for 24h with no server-side revocation mechanism.
`CookieSessionStore` is client-side (encrypted cookie), so there is no way to invalidate
sessions before TTL expiry.

#### 9. BFF proxy duplicates auth-verifier types

**File**: `crate/server/src/routes/ui_auth.rs:330-345`

`ui_auth.rs` manually mirrors `AuthenticationResult` / `CosmianAuthenticationNextStep`
from the auth-verifier crate rather than depending on it. If the auth-verifier adds a new
`next_step` variant, the KMS will silently treat it as an error instead of handling it.

#### 10. Misleading "in memory" println

**File**: `crate/clients/clap/src/actions/login.rs:139-140`

```rust
println!("\nSuccess! The access token was saved in the KMS configuration (in memory)")
```

The token is actually persisted to `ckms.toml` on disk. The message is deceptive about
the security posture.

---

## Positive Security Controls Confirmed

| Control | Location | Assessment |
|---------|----------|------------|
| Algorithm allowlist (asymmetric only) | `token.rs:57-65` | ✅ HS* excluded, prevents algorithm confusion |
| `sub` + `exp` required claims | `token.rs:141` | ✅ Prevents token reuse without identity |
| HTTP-only, Secure, SameSite=Lax session cookie | `start_kms_server.rs:1032-1035` | ✅ Proper cookie security flags |
| Session cookie encryption key derivation | `start_kms_server.rs:504-534` | ✅ Deterministic from public URL + salt for load balancing |
| SPIRE entity_id validation | `spire_token.rs:170-193` | ✅ Rejects empty and default-username entities |
| SPIRE token cache keyed by SHA-256 | `spire_token.rs:52-64` | ✅ Tokens not stored in plaintext in cache |
| Server-side `accept_invalid_certs` defaults to `false` | `cosmian_auth_server_config.rs` | ✅ Secure by default for KMS→AS connections |
| Nonce validation in OIDC flow | `ui_auth.rs:290-294` | ✅ Prevents authorization code injection |
| `Content-Security-Policy: frame-ancestors 'none'` | `start_kms_server.rs:1026` | ✅ Clickjacking protection |
| Payload size limit (64 MB) | `start_kms_server.rs:1040` | ✅ DoS mitigation for KMIP payloads |

---

## Key Files

| Component | Path | Purpose |
|---|---|---|
| SPIRE token middleware | `crate/server/src/middlewares/spire_token.rs` | Vault-token → auth-verifier delegation |
| Cosmian Auth middleware | `crate/server/src/middlewares/cosmian_auth_server/token.rs` | JWKS-based JWT validation |
| Session auth middleware | `crate/server/src/middlewares/session_auth.rs` | Session cookie → user |
| CLI login (Cosmian) | `crate/clients/client/src/http_client/login.rs` | `cosmian_login()` |
| CLI login command | `crate/clients/clap/src/actions/login.rs` | `ckms login cosmian` / `ckms login oauth` |
| CLI action dispatch | `crate/clients/clap/src/actions/kms_actions.rs` | Token persistence to config |
| WebUI login page | `ui/src/pages/LoginPage.tsx` | COSMIAN login form + TOTP |
| WebUI auth context | `ui/src/contexts/AuthContext.tsx` | Session state (no JWT) |
| WebUI app entry | `ui/src/App.tsx` | Auth method detection |
| BFF login proxy | `crate/server/src/routes/ui_auth.rs` | Server-side Cosmian login for WebUI |
| Session cookie config | `crate/server/src/start_kms_server.rs` | SessionMiddleware setup |
| Vault config | `crate/server/src/config/command_line/vault_config.rs` | SPIRE auth-verifier config |
| Cosmian auth config | `crate/server/src/config/command_line/cosmian_auth_server_config.rs` | JWT/JWKS config |
| JWKS manager | `crate/server/src/middlewares/jwt/jwks.rs` | JWKS fetch + cache (60s refresh) |

---

## Conclusion

**Both ckms and WebUI CAN authenticate to the KMS server via auth-verifier** in Mode A
(Cosmian JWT/JWKS flow). The login credentials go to the auth-verifier, and KMS delegates
JWT validation to it via JWKS. This is fully implemented on the `feat/auth-server-integration`
branch.

Mode B (SPIRE/Vault token real-time delegation) is **intentionally not available** to
user-facing clients (ckms or WebUI); it is a machine-to-machine flow for SPIRE agents and
Vault plugins.

### Open items — prioritized

| Priority | Issue | Action |
|----------|-------|--------|
| 🔴 P0 | OAuth `request_token()` hardcodes `accept_invalid_certs: true` | Fix before merge |
| 🔴 P0 | JWT stored in plaintext in `ckms.toml` | Fix before merge (keychain or `0600` perms) |
| 🔴 P0 | Password as CLI arg visible in `ps` | Fix before merge (interactive prompt) |
| 🟡 P1 | No `aud`/`iss` validation on Cosmian JWTs | Add configurable validation |
| 🟡 P1 | JWKS `force_refresh()` DoS amplifier | Rate-limit or cache failure state |
| 🟡 P1 | OAuth `refresh_token` discarded | Store and use for auto-refresh |
| 🟡 P1 | No token refresh for ckms CLI | Detect 401 → prompt re-login |
| 🟢 P2 | 24h session, no revocation | Consider shorter TTL or revocation list |
| 🟢 P2 | BFF proxy duplicates auth-verifier types | Track upstream type changes |
| 🟢 P2 | Misleading "in memory" println | Correct the message |

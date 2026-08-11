# OIDC Integration Plan: auth-verifier as On-Premise OIDC Provider for KMS

**Branch**: `auth_verifier_oidc`
**Submodule**: `authentication` already points to commit `48dafda` (Full OIDC OP)
**Status**: Submodule updated; all KMS code changes still pending.

---

## 1. Problem Statement

The `Cosmian/authentication` server (`auth-verifier`) now ships a **full OpenID Connect
Provider (OP)**. This allows KMS to use an on-premise OIDC identity provider without any
cloud dependency (no Google, Azure, Auth0, or Keycloak required).

The KMS `auth_verifier_oidc` branch has only updated the git submodule pointer.
This plan covers all remaining KMS code changes to integrate the new OIDC OP.

### Goals

- KMS configured via a single `auth_verifier_url` — no separate `ui_oidc_*` section needed.
- Accept both OIDC `at+jwt` access tokens and legacy session JWTs as bearer tokens.
- Enable the standard OIDC Authorization Code + PKCE flow for the Web UI.
- Enable `ckms login cosmian --use-oidc` for CLI users.
- Full test coverage: unit, integration, E2E Playwright, CI harness.

---

## 2. Architecture

```text
Browser / ckms               auth-verifier (OIDC OP)                     KMS server
     │                      ┌───────────────────────────┐               ┌─────────────────┐
     │  GET /oidc/authorize─►  authorization_endpoint    │               │                 │
     │  POST /oidc/token   ─►  token_endpoint            │               │  AuthVerifier   │
     │                      │  → at+jwt (has kid)        │  Bearer token │  middleware     │
     │  Bearer: at+jwt ─────┼────────────────────────────┼──────────────►│  token.rs       │
     │                      │                            │               │                 │
     │  POST /ui/login_as ──┼────────────────────────────┼──────────────►│  BFF login      │
     │  (legacy password)   │  → session JWT (no kid)    │  Bearer token │  ui_auth.rs     │
     │  Bearer: session JWT─┼────────────────────────────┼──────────────►│                 │
     │                      │                            │               │                 │
     │                      │  /oidc/jwks ───────────────┼──────────────►│  JwksManager    │
     │                      │  (combined: OIDC key +     │               │  (combined JWKS)│
     │                      │   session key)             │               │                 │
     │                      └───────────────────────────┘               └─────────────────┘
```

### Key facts about the new OIDC OP

| Endpoint | Path | Notes |
|---|---|---|
| Discovery | `/.well-known/openid-configuration` | Standard RFC 8414 |
| Authorization | `/oidc/authorize` | Authorization Code + PKCE |
| Token | `/oidc/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| JWKS (combined) | `/oidc/jwks` | **OIDC key + session key** — KMS must use this |
| Legacy JWKS | `/.well-known/jwks.json` | Session key only — still present, backward compat |
| Userinfo | `/oidc/userinfo` | Returns `sub`, `preferred_username`, `email`, `roles` |

### Token type differences

| Property | OIDC `at+jwt` access token | Legacy session JWT |
|---|---|---|
| `kid` header | ✅ Present (OIDC signing key ID) | ❌ Absent |
| `typ` header | `at+jwt` | Absent |
| Key lookup | `JwksManager::find(kid)` — fast | Try all keys — fallback |
| Issuer claim | Set to auth-verifier URL | May be absent |

---

## 3. Core Changes

### Task 1 — `AuthVerifier` middleware: handle OIDC `at+jwt` access tokens

**File**: `crate/server/src/middlewares/auth_verifier/token.rs`

Update `verify_auth_verifier_jwt_subject` to dispatch on `kid` presence:

```text
decode JWT header
├── kid present?
│   ├── YES: JwksManager::find(kid)
│   │         ├── found: validate signature with that key → return sub
│   │         └── not found: force_refresh → retry find → error if still missing
│   └── NO (legacy): JwksManager::find_any() → try-all-keys loop (unchanged)
```

Update the module doc comment to describe both token types.

**Unit tests** (in same file, `#[cfg(test)]` module — Task T1):

- `test_oidc_access_token_with_kid_accepted`
- `test_legacy_session_jwt_without_kid_accepted`
- `test_wrong_algorithm_rejected`

---

### Task 2 — Change default JWKS URI to `/oidc/jwks`

**File**: `crate/server/src/config/command_line/auth_verifier_config.rs`

```rust
// Before
format!("{}/.well-known/jwks.json", url.trim_end_matches('/'))
// After
format!("{}/oidc/jwks", url.trim_end_matches('/'))
```

Rationale: `/oidc/jwks` is the **combined** JWKS (OIDC signing key + session key). It
is a strict superset of `/.well-known/jwks.json`, so this change is fully backward-
compatible. OIDC `at+jwt` tokens signed with the dedicated OIDC signing key will only
validate against the combined endpoint.

Update the doc comment and the existing `test_jwks_uri_default` test.

**Unit tests** (Task T2):

- Update `test_jwks_uri_default` → now expects `/oidc/jwks`
- Add `test_explicit_jwks_uri_override_still_works` → confirm `/.well-known/jwks.json`
  can still be set manually via `auth_verifier_jwks_uri`

---

### Task 3 — Add OIDC client fields to `AuthVerifierConfig`

**File**: `crate/server/src/config/command_line/auth_verifier_config.rs`

Add to the `AuthVerifierConfig` struct:

```rust
/// OIDC client ID registered on the auth-verifier for this KMS instance.
///
/// Required when using `ckms login cosmian --use-oidc` or when you want the
/// Web UI to use the OIDC Authorization Code flow (auto-populates `ui_oidc_auth`).
#[clap(long, env = "KMS_AUTH_VERIFIER_OIDC_CLIENT_ID", verbatim_doc_comment)]
pub auth_verifier_oidc_client_id: Option<String>,

/// OIDC client secret for confidential clients.
///
/// Omit for public clients (PKCE-only, `token_endpoint_auth_method = "none"`).
#[clap(long, env = "KMS_AUTH_VERIFIER_OIDC_CLIENT_SECRET", verbatim_doc_comment)]
pub auth_verifier_oidc_client_secret: Option<String>,

/// Space-separated OIDC scopes to request.
///
/// Defaults to `"openid profile email"` when not set.
#[clap(long, env = "KMS_AUTH_VERIFIER_OIDC_SCOPES", verbatim_doc_comment)]
pub auth_verifier_oidc_scopes: Option<String>,
```

Add a helper method:

```rust
/// Returns the effective OIDC scopes as a `Vec<String>`.
/// Defaults to `["openid", "profile", "email"]`.
pub fn oidc_scopes(&self) -> Vec<String> { ... }
```

---

### Task 4 — Auto-populate UI OIDC config from `auth_verifier_url`

**File**: `crate/server/src/config/params/server_params.rs`

In `ServerParams::try_from(ClapConfig)`, after building `auth_verifier_config`, add:

```rust
// Auto-populate ui_oidc_auth when auth_verifier is configured and ui_oidc_auth is empty.
// The auth-verifier IS the OIDC issuer; its discovery document provides all endpoints.
if let Some(ref av_cfg) = auth_verifier_config {
    if av_cfg.is_enabled()
        && conf.ui_config.ui_oidc_auth.ui_oidc_issuer_url.is_none()
        && conf.ui_config.ui_oidc_auth.ui_oidc_client_id.is_none()
    {
        info!(
            "auth_verifier: auto-populating ui_oidc_auth from auth_verifier_url={}",
            av_cfg.auth_verifier_url.as_deref().unwrap_or("")
        );
        conf.ui_config.ui_oidc_auth.ui_oidc_issuer_url =
            av_cfg.auth_verifier_url.clone();
        conf.ui_config.ui_oidc_auth.ui_oidc_client_id =
            av_cfg.auth_verifier_oidc_client_id.clone();
        conf.ui_config.ui_oidc_auth.ui_oidc_client_secret =
            av_cfg.auth_verifier_oidc_client_secret.clone();
    }
}
```

**Unit tests** (Task T3):

- `test_ui_oidc_auto_populated_from_auth_verifier_url`
- `test_ui_oidc_explicit_config_not_overridden`

---

### Task 5 — `ckms` CLI: extend `login cosmian` with `--use-oidc`

#### 5a — `AuthVerifierLoginConfig` (`crate/clients/client/src/http_client/login.rs`)

Add optional OIDC fields:

```rust
pub struct AuthVerifierLoginConfig {
    pub server_url: String,
    pub realm: String,
    /// OIDC client_id (for `--use-oidc` flag)
    pub client_id: Option<String>,
    /// OIDC client_secret (omit for public/PKCE-only clients)
    pub client_secret: Option<String>,
}
```

#### 5b — `LoginSubcommand::Cosmian` (`crate/clients/clap/src/actions/login.rs`)

Add `--use-oidc` flag to the `Cosmian` subcommand variant:

```rust
Cosmian {
    #[clap(long, short = 'u')]
    username: String,
    #[clap(long, short = 'p')]
    password: Option<String>,
    /// Use OIDC Authorization Code + PKCE flow instead of HTTP Basic.
    ///
    /// Requires `cosmian_conf.client_id` to be set.
    /// Opens a browser window; listens on localhost:17899 for the callback.
    #[clap(long, default_value = "false")]
    use_oidc: bool,
}
```

When `--use-oidc` is set, build an `Oauth2LoginConfig` from `cosmian_conf` and call the
existing `LoginState` PKCE flow (same code path as `login oauth`):

```rust
Oauth2LoginConfig {
    client_id: config.client_id.ok_or(...)?,
    client_secret: config.client_secret.unwrap_or_default(),
    authorize_url: format!("{}/oidc/authorize", config.server_url),
    token_url: format!("{}/oidc/token", config.server_url),
    scopes: vec!["openid".into(), "profile".into(), "email".into()],
}
```

**Unit tests** (Task T4):

- `test_ckms_login_cosmian_use_oidc_fails_without_client_id`
- `test_ckms_login_cosmian_use_oidc_help`
- `test_ckms_login_cosmian_password_flow_no_regression`

---

### Task 6 — Update auth wizard

**File**: `crate/server/src/config/wizard/auth_wizard.rs`

In the "Auth Verifier server" wizard branch, after prompting for URL and realm,
add optional OIDC client prompts:

```text
"OIDC client ID (optional — needed for CLI --use-oidc and Web UI OIDC flow):"
"OIDC client secret (optional — leave blank for public/PKCE-only clients):"
```

Write the answers into `auth_verifier.auth_verifier_oidc_client_id` and
`auth_verifier.auth_verifier_oidc_client_secret`.

---

### Task 7 — Update test data configs

**Files**:

- `test_data/configs/server/auth_verifier.toml` — add the three new OIDC fields as
  commented-out examples.
- `test_data/configs/server/auth_verifier_oidc.toml` (new) — complete example showing
  the single-section on-premise OIDC config with no separate `[ui_config.ui_oidc_auth]`:

```toml
# Complete on-premise OIDC setup using auth-verifier as the OIDC Provider.
# No separate [ui_config.ui_oidc_auth] section needed — it is auto-populated.

[auth_verifier]
auth_verifier_url                   = "https://auth.example.com"
auth_verifier_realm                 = "kms"
auth_verifier_oidc_client_id        = "kms-client"
auth_verifier_oidc_client_secret    = "s3cr3t"
# auth_verifier_oidc_scopes         = "openid profile email"   # default
# auth_verifier_accept_invalid_certs = false                   # default

[ui_config]
ui_session_salt = "change-me-in-production"
```

Update the existing unit test `test_auth_verifier_toml_config_parses` in
`auth_verifier_config.rs` to confirm the three new fields parse correctly.

---

### Task 8 — Documentation

**New file**: `documentation/docs/authentication/auth_verifier_oidc.md`

Outline:

1. Introduction — what the on-premise OIDC OP provides
2. Prerequisites — running auth-verifier, creating a realm, registering a client
3. Server configuration — minimal `kms.toml` (single `[auth_verifier]` section)
4. CLI usage — `ckms login cosmian --use-oidc`
5. Web UI usage — automatic OIDC redirect; no extra config
6. Token flow diagram
7. Troubleshooting — JWKS URI, `kid` lookup, TLS cert acceptance

Update:

- `documentation/docs/SUMMARY.md` — add link under the authentication section
- `documentation/docs/authentication/auth_verifier.md` (if it exists) — add cross-reference

---

### Task 9 — CHANGELOG

**File**: `CHANGELOG/auth_verifier_oidc.md`

Entry covering:

- New: on-premise OIDC Provider support via auth-verifier (`feat`)
- New: `auth_verifier_oidc_client_id` / `_client_secret` / `_scopes` config fields
- New: `ckms login cosmian --use-oidc` flag
- Change: default JWKS URI changed from `/.well-known/jwks.json` to `/oidc/jwks`
- Change: `ui_oidc_auth` auto-populated from `auth_verifier_url` (operator convenience)

---

## 4. Test Tasks

### T1 — Unit tests: token type dispatch in `token.rs`

**File**: `crate/server/src/middlewares/auth_verifier/token.rs`

Three tests in `#[cfg(test)]` module (use `insecure` build path — no signature validation):

| Test | What it proves |
|---|---|
| `test_oidc_access_token_with_kid_accepted` | `at+jwt` with `kid` header is accepted; `sub` is returned |
| `test_legacy_session_jwt_without_kid_accepted` | JWT without `kid` is accepted; `sub` is returned |
| `test_wrong_algorithm_rejected` | HS256 token is rejected with `Unauthorized` (production path only) |

---

### T2 — Unit tests: JWKS URI default change

**File**: `crate/server/src/config/command_line/auth_verifier_config.rs`

| Test | Change |
|---|---|
| `test_jwks_uri_default` | Update expected value from `/.well-known/jwks.json` → `/oidc/jwks` |
| `test_explicit_jwks_uri_override_still_works` | New: set `auth_verifier_jwks_uri` to the old URI; confirm it is used as-is |

---

### T3 — Unit tests: auto-populate UI OIDC from `auth_verifier_url`

**File**: `crate/server/src/config/params/server_params.rs`

| Test | What it proves |
|---|---|
| `test_ui_oidc_auto_populated_from_auth_verifier_url` | `ui_oidc_issuer_url` is set to `auth_verifier_url` when `ui_oidc_auth` is empty |
| `test_ui_oidc_explicit_config_not_overridden` | Explicit `ui_oidc_auth` values are NOT replaced by auto-populate |

---

### T4 — ckms CLI unit tests: `--use-oidc` early exits

**File**: `crate/clients/ckms/src/tests/login_tests.rs`

All three tests run without a server or browser:

| Test | What it proves |
|---|---|
| `test_ckms_login_cosmian_use_oidc_fails_without_client_id` | `--use-oidc` without `client_id` in `cosmian_conf` → error mentioning `client_id` |
| `test_ckms_login_cosmian_use_oidc_help` | `login cosmian --help` mentions `--use-oidc` |
| `test_ckms_login_cosmian_password_flow_no_regression` | Without `--use-oidc`, behavior is unchanged (fails with `cosmian_conf` missing) |

---

### T5 — Rust integration test: OIDC `at+jwt` accepted as bearer token

**File**: `crate/test_kms_server/src/auth_verifier_tests.rs`

```text
#[ignore = "requires running KMS+auth-verifier OIDC; invoke via .mise/scripts/test/test_ui_auth_oidc.sh"]
async fn test_kmip_request_with_oidc_access_token()
```

Flow:

1. `POST {AUTH_VERIFIER_URL}/oidc/token` with `client_credentials` grant → obtain `access_token` (`at+jwt`)
2. `POST {KMS_URL}/kmip/2_1` with `Authorization: Bearer <access_token>` and empty body
3. Assert HTTP **422** (KMIP parse error, not **401** unauthorized or **403** forbidden)

Uses env vars: `AUTH_VERIFIER_URL`, `KMS_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`.

---

### T6 — Playwright E2E: on-premise OIDC login

**File**: `ui/tests/e2e-oidc/auth-verifier-oidc-login.spec.ts` (new)

All tests are guarded by `test.skip(!AUTH_VERIFIER_OIDC_TEST_USERNAME || ...)`.

| Test | Description |
|---|---|
| `GET /ui/auth_method reports JWT` | OIDC flow uses the standard JWT auth method |
| `TC1 — happy path login` | Click OIDC button → auth-verifier `/oidc/authorize` → fill creds → callback → authenticated |
| `TC2 — no token in browser` | `/ui/whoami` returns `{ user_id }` only; no JWT in localStorage/sessionStorage |
| `TC3 — session + logout` | Session persists across reload; logout clears it; `/ui/whoami` → 401 |

---

### T7 — CI harness: `test_ui_auth_oidc.sh` + MISE task

**File**: `.mise/scripts/test/test_ui_auth_oidc.sh` (new)

Steps:

1. Build WASM, KMS server, auth-verifier binary (same as `test_ui_auth.sh`)
2. Start auth-verifier on a dynamic port with the dev config + OIDC enabled
3. Register an OIDC client via `POST {auth_url}/admin/realms/_/clients` (JSON body)
4. Write a KMS config with `[auth_verifier]` pointing at auth-verifier, OIDC client fields set
5. Start KMS on a dynamic port
6. Run Playwright tests: `pnpm run test:e2e:auth-verifier-oidc`
7. Run Rust test: `cargo test -p test_kms_server -- --ignored test_kmip_request_with_oidc_access_token`
8. Emit failure logs if either test run fails; clean up processes

**MISE task** in `mise.toml`:

```toml
[tasks."test:ui-auth-oidc"]
description = "E2E tests for on-premise OIDC via auth-verifier"
run = "bash .mise/scripts/test/test_ui_auth_oidc.sh"
```

---

## 5. Dependency Graph

```text
t1-middleware-kid ──────────────────────────────────────► tt1-unit-token
t2-jwks-uri ────────────────────────────────────────────► tt2-unit-jwks-uri
t3-oidc-fields ──► t4-auto-populate ────────────────────► tt3-unit-server-params
t3-oidc-fields ──► t5-cli-oidc ─────────────────────────► tt4-cli-unit
t6-wizard     (independent)
t7-test-data  (independent)
t8-docs       (independent)
t9-changelog  (independent)

t1 + t2 + t4 ──────────────────────────────────────────► tt5-integration ──► tt7-ci-harness
t4            ──────────────────────────────────────────► tt6-playwright  ──► tt7-ci-harness
```

**Parallel batches**:

- **Batch A** (independent): t1, t2, t3, t6, t7, t8, t9
- **Batch B** (after t3): t4, t5
- **Batch C** (after t4+t5): tt3, tt4
- **Batch D** (after t1+t2+t4): tt5, tt6
- **Batch E** (after tt5+tt6): tt7

---

## 6. Files Changed Summary

| File | Change type |
|---|---|
| `crate/server/src/middlewares/auth_verifier/token.rs` | Modify: `kid`-dispatch + unit tests |
| `crate/server/src/config/command_line/auth_verifier_config.rs` | Modify: new fields, JWKS URI default, tests |
| `crate/server/src/config/params/server_params.rs` | Modify: auto-populate logic + unit tests |
| `crate/server/src/config/wizard/auth_wizard.rs` | Modify: OIDC client prompts |
| `crate/clients/client/src/http_client/login.rs` | Modify: `AuthVerifierLoginConfig` new fields |
| `crate/clients/clap/src/actions/login.rs` | Modify: `--use-oidc` flag + PKCE dispatch |
| `crate/clients/ckms/src/tests/login_tests.rs` | Modify: 3 new unit tests |
| `crate/test_kms_server/src/auth_verifier_tests.rs` | Modify: new `#[ignore]` integration test |
| `test_data/configs/server/auth_verifier.toml` | Modify: add OIDC fields as comments |
| `test_data/configs/server/auth_verifier_oidc.toml` | **New**: complete OIDC example |
| `ui/tests/e2e-oidc/auth-verifier-oidc-login.spec.ts` | **New**: Playwright E2E spec |
| `.mise/scripts/test/test_ui_auth_oidc.sh` | **New**: CI test harness |
| `mise.toml` | Modify: add `test:ui-auth-oidc` task |
| `documentation/docs/authentication/auth_verifier_oidc.md` | **New**: documentation page |
| `documentation/docs/SUMMARY.md` | Modify: add nav link |
| `CHANGELOG/auth_verifier_oidc.md` | **New**: changelog entry |

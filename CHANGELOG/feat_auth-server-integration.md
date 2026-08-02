## Features

- **`ckms login approle`**: add Vault-compatible `AppRole` login for automation and service accounts. Exchanges a `role_id` (+ optional `secret_id`) for a Vault-compatible token via the KMS `POST /v1/auth/approle/login` endpoint (which the KMS proxies to the auth-verifier), stores it in `http_config.vault_token`, and forwards it as an `X-Vault-Token` header on every subsequent KMS request where the SPIRE-token middleware validates it.
    - New `approle_login()` async helper in `cosmian_kms_client` (reuses the full TLS/proxy stack via `HttpClient`).
    - New `vault_token` field on `HttpClientConfig`, injected as an `X-Vault-Token` header (mutually exclusive with the `access_token` `Authorization: Bearer` header).
    - `ckms login approle --role-id <id> [--secret-id <sid>]` CLI subcommand; `--secret-id` is prompted interactively (without echo) when omitted.
    - `LoginAction::process()` now returns a `LoginCredential` enum (`AccessToken` / `VaultToken`) so the caller persists the credential to the correct config field; `ckms logout` clears both.

## Security

- **OAuth2 token exchange no longer disables TLS verification**: `request_token()` previously hard-coded `accept_invalid_certs: true`, unconditionally disabling certificate validation for the OAuth2 token endpoint (where the authorization code and PKCE verifier are transmitted). Certificate validation is now enabled, closing a MITM vector.
- **Interactive, no-echo secret input for `ckms login`**: `--password` (for `login cosmian`) and `--secret-id` (for `login approle`) are now optional; when omitted, they are read interactively without echoing, so credentials no longer need to appear in shell history, `ps` output, or `/proc/*/cmdline`.

    - `cosmian_login()` accepts an optional `totp_code: Option<&str>` parameter; includes it in the JSON request body when provided.
    - Parses the server's `AuthenticationResult` JSON (`next_step`: `Authenticated` / `TotpRequired` / `ChangePassword`) before extracting the `_ea_` session cookie, replacing the previous cookie-only detection that produced a confusing error on TOTP-protected accounts.
    - `CosmianLoginStep` return enum distinguishes `Authenticated(token)` from `TotpRequired`.
    - On `TotpRequired`, the CLI prompts interactively (`dialoguer::Input`) and re-submits; fails with a clear error in non-TTY environments.
    - `ChangePassword` returns an actionable error message instead of a silent failure.
    - Add `dialoguer` workspace dependency to `cosmian_kms_cli_actions`.

- **`ckms login cosmian`**: implement Cosmian authentication server login via `POST /login?realm=<realm>` with HTTP Basic credentials (`Authorization: Basic <base64(username:password)>`).
    - Add `CosmianLoginConfig` struct (`server_url`, `realm`) to `cosmian_kms_client`.
    - Add `cosmian_conf` field to `HttpClientConfig` (separate from `oauth2_conf`).
    - Add `cosmian_login` async helper in the HTTP client library.
    - `ckms login cosmian --username <u> --password <p>` CLI subcommand.

- **Cosmian auth server middleware (server-side)**: add `CosmianAuth` middleware so the KMS server can validate bearer tokens issued by the Cosmian authentication server.
    - New `CosmianAuthConfig` struct (`--cosmian-auth-server-url`, `--cosmian-auth-jwks-uri`, `--cosmian-auth-accept-invalid-certs` / env `KMS_COSMIAN_AUTH_SERVER_URL`).
    - New `crate/server/src/middlewares/cosmian_auth/` module: fetches JWKS via `JwksManager`, tries every key when no `kid` is present, uses `sub` claim as user identity (not `email`).
    - `JwksManager::find_any()` helper returns all keys regardless of `kid`.
    - Middleware registered on all authenticated scopes: default (`/`), `/v1/crypto`, `/ms_dke`, `/tokenize`.
    - `EnsureAuth` boolean conditions updated to include `use_cosmian_auth`.
    - Auth wizard updated with "Cosmian authentication server" option.
    - Test server config: `test_data/configs/server/test/auth_cosmian.toml`.

- **Web UI login for the Cosmian authentication server ("AS")**: the KMS Web UI can now authenticate end users against the proprietary Cosmian authentication server, mirroring `ckms login cosmian` CLI parity, using the same BFF session-cookie pattern as the OIDC flow below — the AS's JWT never reaches the browser.
    - New `POST /ui/login_as` route: accepts `{ username, password, totp_code? }` from the browser, replays it as HTTP Basic auth against `{cosmian_auth_server_url}/login?realm={realm}` (same request `ckms login cosmian` makes), extracts the `_ea_` session JWT from the AS's `Set-Cookie` response header, validates it via the JWKS-backed `verify_cosmian_jwt_subject` (shared with the bearer-token `CosmianAuth` middleware), then stores only the resulting `sub` (username) in the actix session — never the JWT itself.
    - Handles the AS's `next_step` state machine (`Authenticated` / `TotpRequired` / `ChangePassword`), matching `ckms login cosmian`'s TOTP support: the frontend re-submits with `totp_code` when `TotpRequired` is returned, and surfaces an actionable error on `ChangePassword`.
    - New `cosmian_auth_realm` config field (`--cosmian-auth-realm` / env `KMS_COSMIAN_AUTH_REALM`) and `CosmianAuthConfig::ui_login_enabled()` (`true` only when both `cosmian_auth_server_url` and `cosmian_auth_realm` are set) — bearer-token validation of already-issued tokens continues to work without a realm.
    - `GET /ui/auth_method` now returns `"COSMIAN"` when UI login for the Cosmian auth server is enabled (new `auth_type` branch in `start_kms_server.rs`), alongside the existing `"JWT"`/`"CERT"`/`None`.
    - Auth wizard (`--config-wizard`) prompts to enable the Web UI login form and set the realm when the Cosmian authentication server option is selected.
    - Frontend: `AuthMethod` extended with `"COSMIAN"`; new `loginCosmian()` helper (`src/utils/utils.ts`) posting to `/ui/login_as`; `LoginPage` renders a username/password form (switching to a one-time-code prompt on `TotpRequired`) when `authMethod === "COSMIAN"`; `App.tsx`'s auth bootstrap and route guard, and `MainLayout`'s header (session user tag + Logout button), now treat `"COSMIAN"` the same as `"JWT"` since both are session-cookie-based.

## Refactor

- **BFF (Backend for Frontend) OIDC pattern for the Web UI**: rework the OIDC authentication flow to eliminate token leakage to the browser.
    - Discovery document (`authorization_endpoint`/`token_endpoint`) and the initial JWKS are fetched once at server startup (`build_oidc_runtime_config()`) and cached in `OidcRuntimeConfig`; `authorization_endpoint`/`token_endpoint` require a server restart to pick up changes.
    - JWKS signing keys use a "refresh-on-miss" strategy: if `/ui/callback` receives an `id_token` whose `kid` is not in the cached JWKS (e.g. the IdP rotated its signing keys), the `JwksManager` is refreshed on demand and the lookup retried once, so login succeeds without restarting the server. This mirrors the existing refresh-on-miss pattern used by the Cosmian auth middleware.
    - After OIDC callback, only `user_id` is stored in the actix-session cookie; `id_token` is never forwarded to the browser.
    - New `SessionAuth` middleware reads the session cookie on every request and injects `AuthenticatedUser` when a valid session exists; registered on `default_scope`, `crypto_scope`, and `tokenize_scope`.
    - `/ui/token` endpoint renamed to `/ui/whoami`; response is `{ user_id: String }` only (no token).
    - UI updated: `fetchIdToken` → `fetchWhoAmI`, `idToken` state removed from `AuthContext` and all action components; Bearer `Authorization` headers removed from all client-side API calls.
    - `getNoTTLVRequest`, `sendKmipRequest`, `postNoTTLVRequest`, `getNoTTLVRequestWithTimeout` signatures drop the `idToken` parameter.
    - `useActionState` hook no longer exposes `idToken`.

- Extracted `validate_cosmian_token` into `pub(crate) async fn verify_cosmian_jwt_subject(jwks_manager, token) -> KResult<String>`, returning just the validated `sub` claim instead of an `AuthenticatedUser`, so it can be shared between the bearer-token `CosmianAuth` middleware and the new `/ui/login_as` handler without duplicating JWT/JWKS trust logic.
- Added `CosmianAuthRuntimeConfig` (mirrors `OidcRuntimeConfig`): bundles the static `CosmianAuthConfig` with the already-built `JwksManager` `Arc` and is injected as `app_data` on the `/ui` scope — no second JWKS manager/fetch is created for the UI login path.
- `logout()` no longer falls back to a `500 "Logout URL is missing"` response when no OIDC logout URL is configured (e.g. a Cosmian-auth-only or unconfigured-OIDC session): it now purges the session and redirects to `/ui/login`, same as a normal OIDC logout's final hop.

## Bug Fixes

- Fixed a pre-existing `cfg` mismatch in `cosmian_auth_token.rs`: the `ALLOWED_ALGORITHMS` const (and its `Algorithm` import) were gated on `not(feature = "insecure")` but only ever read under `all(not(test), not(feature = "insecure"))`, making `cargo test -p cosmian_kms_server` fail to compile (`error: constant ALLOWED_ALGORITHMS is never used`) on any normal test build. Aligned both `cfg` attributes.

## Documentation

- Added `CHANGELOG/test_plan_cosmian-auth-ui-login.md`: manual end-to-end test plan for the new Web UI login flow (happy path, TOTP, bad credentials, `ChangePassword`, logout, no-token-in-browser check), following the precedent set by `test_plan_oidc-session-auth.md` since there is no mock/wiremock harness for a live external Cosmian authentication server in this repo.

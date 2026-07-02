## Features

- **`ckms login cosmian` TOTP support**: `ckms login cosmian` now handles accounts with TOTP enabled on the Cosmian authentication server.
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

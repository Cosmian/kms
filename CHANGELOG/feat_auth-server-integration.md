## Features

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

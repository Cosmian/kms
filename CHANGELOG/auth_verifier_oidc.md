# Changelog — auth_verifier_oidc

## feat: on-premise OIDC Provider support via auth-verifier

The `authentication` submodule has been updated to include a full
**OpenID Connect Provider (OP)**. KMS can now use the on-premise auth-verifier
as an OIDC identity provider, eliminating cloud dependencies for OIDC-based
authentication.

### New features

#### KMS server
- **`auth_verifier_oidc_client_id`** (`KMS_AUTH_VERIFIER_OIDC_CLIENT_ID`): OIDC
  client ID registered on the auth-verifier; enables CLI `--use-oidc` and Web UI
  OIDC flow.
- **`auth_verifier_oidc_client_secret`** (`KMS_AUTH_VERIFIER_OIDC_CLIENT_SECRET`):
  OIDC client secret for confidential clients.
- **`auth_verifier_oidc_scopes`** (`KMS_AUTH_VERIFIER_OIDC_SCOPES`): space-separated
  OIDC scopes to request (defaults to `openid profile email`).
- **Auto-populate `ui_oidc_auth`**: when `auth_verifier_url` is configured and
  `[ui_config.ui_oidc_auth]` is empty, the KMS automatically derives the OIDC
  issuer URL and client credentials from the `[auth_verifier]` section.
- **Auth wizard**: optional OIDC client ID / secret prompts in the Auth Verifier
  wizard path.

#### KMS client (`ckms`)
- **`ckms login cosmian --use-oidc`**: new flag on the `login cosmian` subcommand
  that triggers the OIDC Authorization Code + PKCE flow against the auth-verifier,
  instead of the HTTP Basic credential flow.

### Changed

- **Default JWKS URI** changed from `{auth_verifier_url}/.well-known/jwks.json` to
  `{auth_verifier_url}/oidc/jwks`.  The combined JWKS (`/oidc/jwks`) contains both
  the dedicated OIDC signing key and the legacy session key, making it a strict
  superset.  **Backward-compatible**: the old URI can still be set explicitly via
  `auth_verifier_jwks_uri`.

### Middleware improvement

- The `AuthVerifier` bearer-token middleware now dispatches on the `kid` JWT header:
  - **`kid` present** (OIDC `at+jwt` access tokens): fast direct key-lookup via
    `JwksManager::find(kid)` with refresh-on-miss for key rotation.
  - **No `kid`** (legacy session JWTs): unchanged try-all-keys fallback.
  - Both token types are accepted simultaneously; no configuration change required.

## Bug Fixes

- `build_oidc_runtime_config`: propagate `auth_verifier_accept_invalid_certs` to
  the reqwest client used for OIDC discovery so self-signed certs in dev
  environments are accepted without extra configuration.
- `build_oidc_runtime_config`: also propagate `accept_invalid_certs` to the
  JwksManager built for the OIDC signing-key JWKS endpoint.
- OIDC callback (`/ui/callback`): set `danger_accept_invalid_certs` on the reqwest
  client used for the authorization-code token exchange so it can reach
  auth-verifier over a self-signed TLS connection.
- OIDC callback: use `sub` claim as the primary user identity (auth-verifier OIDC
  `sub` = username), falling back to `email` for cloud IdPs — previously the
  callback required `email`, causing a 500 when auth-verifier tokens omitted it.

## Changed

- `test_data/configs/server/auth_verifier_oidc.toml`: removed the redundant
  `auth_verifier_oidc_client_id` / `auth_verifier_oidc_client_secret` fields from
  `[auth_verifier]` — those fields are only needed for Option B (auto-populate);
  this file uses Option A (explicit `[ui_config.ui_oidc_auth]`), where the
  credentials belong exclusively in that section.
- `OidcClientSecretModal`: config snippet now shows `[ui_config.ui_oidc_auth]`
  (not `[auth_verifier]`) and uses the dynamic server URL as the issuer.

## Bug Fixes

- **"Missing PKCE verifier" in OIDC callback**: `SameSite=Lax` session cookies
  (containing the PKCE verifier) were withheld by browsers on the cross-site
  POST→redirect chain from the auth-verifier IdP back to the KMS callback URL
  (RFC 6265bis §5.2.2). Fixed by encoding `{pkce_verifier, nonce, exp}` in the
  OIDC `state` parameter as a signed HS256 JWT (per RFC 7636 §4.3 and RFC 6749
  §4.1.1 which guarantees `state` is returned unchanged). The session cookie is
  now only used post-callback to store `user_id` — no session dependency during
  the cross-site redirect phase.
- Added `state_hmac_key: [u8; 32]` to `OidcDiscoveredEndpoints`, derived at
  startup from `SHA-256("oidc-state-v1|{kms_public_url}|{ui_session_salt}")`.

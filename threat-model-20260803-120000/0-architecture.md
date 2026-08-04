# Architecture Overview — KMS Authentication Subsystem (Spire Branch)

**Analysis date**: 2026-08-03
**Scope**: Authentication middleware stack (spire branch delta)
**Analyst**: AI Threat Model Analyst
**Baseline**: `origin/spire` branch vs `feat/auth-server-integration` (HEAD)

## System Description

The Cosmian KMS authentication subsystem validates incoming requests through a layered middleware stack. The spire branch introduces three new authentication paths: (1) SPIRE/Vault-compatible token validation via `X-Vault-Token` headers, (2) a Cosmian Auth Verifier JWT middleware for bearer tokens without `kid` headers, and (3) a session-based UI authentication middleware. An unauthenticated auth proxy forwards SPIRE auth requests to an external auth-verifier service.

## Component Inventory

| Component | Location | Purpose | Trust Level |
|-----------|----------|---------|-------------|
| SPIRE Token Middleware | `crate/server/src/middlewares/spire_token.rs` | Validates `X-Vault-Token` via auth-verifier `lookup-self` API; 30s in-memory cache | Semi-trusted (depends on auth-verifier) |
| Auth Verifier Middleware | `crate/server/src/middlewares/auth_verifier/` | Validates Cosmian Auth Verifier JWTs (no `kid`); tries all JWKS keys | Semi-trusted (depends on JWKS integrity) |
| Session Auth Middleware | `crate/server/src/middlewares/session_auth.rs` | Reads `user_id` from actix-session cookie for UI browser requests | Trusted (server-side session) |
| SPIRE Auth Proxy | `crate/server/src/routes/spire/auth_proxy.rs` | Unauthenticated reverse proxy for `/v1/auth/*` → auth-verifier `/auth/*` | **Untrusted boundary** (public-facing) |
| JWKS Manager | `crate/server/src/middlewares/jwt/jwks.rs` | Fetches and caches JWKS from IdP/Auth Verifier; `find_any()` for no-kid tokens | Semi-trusted (network fetch) |
| JWT Auth Middleware | `crate/server/src/middlewares/jwt/jwt_config.rs` | Standard OIDC JWT validation with `kid`-based key lookup | Semi-trusted |
| API Token Middleware | `crate/server/src/middlewares/api_token/` | Static API token validation (Bearer) | Trusted |
| TLS Auth Middleware | `crate/server/src/middlewares/tls_auth.rs` | mTLS client certificate extraction | Trusted |
| Ensure Auth Middleware | `crate/server/src/middlewares/ensure_auth.rs` | Fallback: enforces at least one auth method; injects `default_username` if none configured | Trusted |
| Auth Verifier Config | `crate/server/src/config/command_line/auth_verifier_config.rs` | Configuration for Auth Verifier URL, JWKS URI, realm, TLS settings | Configuration (operator-controlled) |
| Server Params (Vault) | `crate/server/src/config/params/server_params.rs` | Vault-compatible API params: `vault_auth_verifier_url`, cache TTL, TLS settings | Configuration (operator-controlled) |

## Asset Inventory

| Asset | Location | Sensitivity | Protection |
|-------|----------|-------------|-----------|
| SPIRE/Vault tokens | `X-Vault-Token` header | CRITICAL | SHA-256 hashed for cache; never stored in plaintext |
| Auth Verifier JWTs | `Authorization: Bearer` header | CRITICAL | Signature validated against JWKS; not persisted |
| JWKS public keys | `JwksManager` in-memory cache | HIGH | Fetched over TLS; cached with 60s refresh throttle |
| Session cookie (`user_id`) | Actix-session encrypted cookie | HIGH | Server-side encryption; salt-derived key |
| Auth-verifier URL + CA cert | Server config / env vars | CRITICAL | Not persisted in DB; operator-provided |
| `accept_invalid_certs` flags | Server config | CRITICAL | Defaults to `false`; dev/test only |
| SpireTokenCache (in-memory) | `DashMap<[u8;32], CacheEntry>` | MEDIUM | Process-local; 30s TTL; 100K max entries |
| Entity IDs (SPIRE identities) | Request extensions → KMS permissions | HIGH | Validated against empty/default_username collision |

## Trust Boundary Summary

| Boundary | What Crosses It | Direction |
|----------|----------------|-----------|
| **TLS Termination** | HTTPS requests from Internet | Inbound |
| **Auth Middleware Stack** | Bearer tokens, `X-Vault-Token`, mTLS certs, session cookies | Inbound |
| **Auth-Verifier Network Call** | `GET /auth/token/lookup-self` (SPIRE token validation) | Outbound (KMS → auth-verifier) |
| **JWKS Fetch** | `GET /.well-known/jwks.json` (key material download) | Outbound (KMS → IdP/auth-verifier) |
| **Auth Proxy** | `/v1/auth/*` requests forwarded to auth-verifier | Outbound (unauthenticated proxy) |
| **Session Cookie** | Encrypted `user_id` in browser cookie | Bidirectional |
| **Request Extensions** | `AuthenticatedUser` injected into actix extensions | Internal (middleware → handler) |

## Middleware Execution Order (LIFO)

Actix-web evaluates `.wrap()` calls in **last-in, first-out** order. The effective execution order for KMIP/UI scopes:

```text
Request → Cors → VaultToken(optional) → TlsAuth → JwtAuth → ApiToken → SessionAuth → EnsureAuth → Handler
```

For SPIRE-only transit/PKI scopes:

```text
Request → Cors → SpireToken(strict) → Handler
```

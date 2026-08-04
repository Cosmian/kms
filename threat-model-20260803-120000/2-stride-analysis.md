# STRIDE-A Analysis — KMS Authentication Subsystem (Spire Branch)

## Analysis Matrix

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
|----|----------------------|-------------|-------------------|----------|----------|-----|--------|
| T-001 | Auth Proxy `/v1/auth/*` | Spoofing | Unauthenticated proxy could allow an attacker to reach auth-verifier endpoints beyond `/auth/*` if path normalization differs between actix and reqwest | `auth_proxy.rs:path_has_dot_segment()` | 6.5 | CWE-918 | Confirmed (mitigated) |
| T-002 | Auth Verifier JWT | Spoofing | Token without `kid` tries all JWKS keys; if JWKS is poisoned via MITM (accept_invalid_certs=true), attacker can forge tokens | `auth_verifier/token.rs:verify_auth_verifier_jwt_subject()` | 7.5 | CWE-287 | Confirmed (conditional) |
| T-003 | SPIRE Token Cache | Spoofing | SHA-256 hash collision in token cache could map attacker's token to a valid cached identity | `spire_token.rs:check_vault_token()` | 3.1 | CWE-294 | Not confirmed (SHA-256 collision infeasible) |
| T-004 | JWKS Fetch | Tampering | MITM on JWKS fetch when `accept_invalid_certs=true` allows injecting attacker's public key, enabling forged JWT validation | `jwks.rs:parse_jwks()` — `danger_accept_invalid_certs(accept_invalid_certs)` | 7.5 | CWE-295 | Confirmed (conditional) |
| T-005 | Auth Proxy Response | Tampering | Auth-verifier response forwarded byte-for-byte; if auth-verifier is compromised, attacker controls all auth decisions for SPIRE clients | `auth_proxy.rs:proxy_auth_request()` — `resp.bytes().await` | 5.3 | CWE-345 | Confirmed (design limitation) |
| T-006 | SPIRE Token Validation | Repudiation | No per-request audit log distinguishing SPIRE auth from native auth methods; operator cannot determine which auth method was used for a given KMIP operation | `spire_token.rs` — no audit log call; `AuthenticatedUser` struct has no `auth_method` field | 4.3 | CWE-778 | Confirmed |
| T-007 | Auth Verifier JWT | Information Disclosure | Error messages from JWT validation include JWKS key material in log output | `jwt_config.rs:L167` — `"Looking for kid`{kid}`in JWKS:\n{:?}"` | 5.3 | CWE-209 | Confirmed |
| T-008 | `accept_invalid_certs` | Information Disclosure | Flag defaults to `false` but is configurable via env var; if set in production, all TLS verification for auth-verifier/JWKS is disabled | `auth_verifier_config.rs:auth_verifier_accept_invalid_certs`, `server_params.rs:vault_auth_verifier_accept_invalid_certs` | 7.4 | CWE-295 | Confirmed (config risk) |
| T-009 | Auth Proxy DoS | Denial of Service | Unauthenticated proxy can be used to flood auth-verifier with requests; no rate limiting on the proxy scope itself | `auth_proxy.rs` — no rate limiter; `start_kms_server.rs` — proxy scope has no auth middleware | 7.5 | CWE-770 | Confirmed |
| T-010 | SPIRE Token Cache | Denial of Service | Cache bounded to 100K entries but each entry holds a `SpireAuthenticatedUser` with `Vec<String>` policies; memory exhaustion possible with many unique valid tokens | `spire_token.rs:DEFAULT_MAX_ENTRIES = 100_000` | 4.3 | CWE-770 | Confirmed (bounded) |
| T-011 | `force_refresh()` | Denial of Service | Empty JWKS cache triggers unthrottled `force_refresh()`; repeated requests with invalid tokens could hammer the JWKS endpoint | `jwks.rs:force_refresh()` — called from `auth_verifier/token.rs` when `jwks.is_empty()` | 5.3 | CWE-770 | Confirmed (conditional) |
| T-012 | Optional Vault Token MW | Elevation of Privilege | When `vault_api_enabled=true`, a valid SPIRE token grants access to KMIP, MS-DKE, and tokenize scopes — not just transit/PKI — bypassing native auth entirely | `start_kms_server.rs` — `vault_token_optional_middleware` on KMIP, MS-DKE, tokenize scopes | 6.5 | CWE-284 | Confirmed (by design) |
| T-013 | Entity ID Validation | Elevation of Privilege | `validated_entity()` rejects empty and default_username collision, but does not reject other privileged usernames (e.g., admin-created service accounts) | `spire_token.rs:validated_entity()` — only checks `trim().is_empty()` and `== default_username` | 5.9 | CWE-285 | Confirmed (partial mitigation) |
| T-014 | Session Cookie | Spoofing | Session cookie `user_id` is the sole auth for UI requests; if session salt is weak or shared across environments, session forgery is possible | `session_auth.rs` — `session.get::<String>("user_id")` | 5.3 | CWE-331 | Confirmed (conditional) |
| T-015 | Auth Proxy Header Forwarding | Abuse | Proxy forwards `Authorization` header to auth-verifier; if auth-verifier has admin endpoints outside `/auth/*` that accept Authorization, the proxy becomes an SSRF vector | `auth_proxy.rs` — forwards `Authorization` header; path check only blocks dot segments | 6.5 | CWE-918 | Confirmed (mitigated by path scope) |
| T-016 | `insecure` Feature Flag | Elevation of Privilege | Both JWT and Auth Verifier middlewares skip signature validation when `feature = "insecure"` or `cfg(test)`; if compiled into production binary, all token validation is bypassed | `auth_verifier/token.rs:insecure_decode`, `jwt_config.rs:insecure_decode` | 9.0 | CWE-287 | Confirmed (build config) |
| T-017 | SPIRE Transit Key Ownership | Abuse | SPIRE-authenticated users can create transit keys that persist in the KMS database; no per-entity quota or automatic cleanup | `routes/spire/transit.rs:create_transit_key()` — no quota check | 4.3 | CWE-770 | Confirmed |

## Threat Narrative

### T-001: Auth Proxy Path Traversal (Confirmed — Mitigated)

**Attack scenario**: An attacker sends `POST /v1/auth/%2e%2e/admin/config` to the KMS auth proxy. If the path normalization differs between actix-web (which does NOT normalize) and reqwest's URL parser (which DOES normalize `..`), the request could reach `/admin/config` on the auth-verifier.

**Pre-conditions**: Network access to the KMS HTTP endpoint.

**Impact**: Unauthorized access to auth-verifier admin endpoints; potential credential theft or configuration change.

**Evidence**: `auth_proxy.rs:path_has_dot_segment()` explicitly checks for `.`, `..`, `%2e`, `%2E`, and backslash variants. The check splits on both `/` and `\` to handle WHATWG URL parser behavior.

**Mitigations present**: Comprehensive path traversal check covering plain, percent-encoded, and backslash variants. Unit tests verify all encoding combinations.

**Gaps**: The check is application-level; a future change to the URL parser or path handling could reintroduce the vulnerability. No defense-in-depth (e.g., auth-verifier-side path restriction).

---

### T-002: Auth Verifier JWT Forgery via JWKS Poisoning (Confirmed — Conditional)

**Attack scenario**: When `accept_invalid_certs=true`, an attacker performing MITM on the KMS→auth-verifier connection can inject a rogue JWKS containing their public key. Since Auth Verifier tokens lack `kid`, the `find_any()` method tries all keys — including the injected one — and validates a forged token.

**Pre-conditions**: Network position for MITM (e.g., same network segment, compromised proxy) AND `accept_invalid_certs=true` in KMS config.

**Impact**: Complete authentication bypass — attacker can forge valid tokens for any identity.

**Evidence**: `jwks.rs:parse_jwks()` passes `danger_accept_invalid_certs(accept_invalid_certs)` to the reqwest client. `auth_verifier/token.rs:verify_auth_verifier_jwt_subject()` calls `jwks_manager.find_any()` and tries every key.

**Mitigations present**: Flag defaults to `false`. Documentation explicitly warns "Development and testing only."

**Gaps**: No runtime warning or health-check indicator when the flag is enabled. An operator could enable it for testing and forget to disable it.

---

### T-009: Auth Proxy as DoS Amplifier (Confirmed)

**Attack scenario**: An attacker sends a high volume of requests to `/v1/auth/*` on the KMS. The proxy forwards each request to the auth-verifier without any rate limiting at the proxy scope level. The auth-verifier becomes overwhelmed, causing legitimate SPIRE agents to fail authentication.

**Pre-conditions**: Network access to the KMS HTTP endpoint. No authentication required.

**Impact**: Denial of service for all SPIRE-authenticated clients. The KMS itself remains operational but SPIRE agents cannot authenticate.

**Evidence**: `start_kms_server.rs` — the `/v1/auth` scope has no rate limiter middleware. The global rate limiter (if configured) applies per-source-IP but the proxy scope is unauthenticated, so IP-based rate limiting is the only defense.

**Mitigations present**: Global rate limiter (if `rate_limit_per_second` is configured). The proxy returns 502 quickly if auth-verifier is unreachable (no long timeout).

**Gaps**: Rate limiting is optional (disabled by default). No per-scope rate limit for the auth proxy. No circuit breaker for auth-verifier calls.

---

### T-012: SPIRE Token Grants Cross-Scope Access (Confirmed — By Design)

**Attack scenario**: A SPIRE agent with a valid `X-Vault-Token` accesses the KMIP scope (`/kmip/2_1`) via `vault_token_optional_middleware`. The SPIRE identity becomes the `AuthenticatedUser`, gaining access to any KMIP object owned by that identity — including objects created via native auth.

**Pre-conditions**: `vault_api_enabled=true` and valid SPIRE token.

**Impact**: SPIRE identities have the same access scope as native-auth identities. If a SPIRE identity collides with a native username (other than `default_username`), it inherits that user's permissions.

**Evidence**: `start_kms_server.rs` — `vault_token_optional_middleware` is applied to KMIP, MS-DKE, and tokenize scopes. `spire_token.rs:validated_entity()` only rejects `default_username` collision, not other native usernames.

**Mitigations present**: `validated_entity()` prevents collision with `default_username`. KMS permission system still enforces per-object access control.

**Gaps**: No namespace separation between SPIRE and native identities. A SPIRE entity named "alice" would have the same permissions as a native "alice".

---

### T-016: `insecure` Feature Bypasses All Validation (Confirmed — Build Config)

**Attack scenario**: If the KMS binary is compiled with `--features insecure`, both JWT and Auth Verifier middlewares skip signature validation entirely, using `danger::insecure_decode`. An attacker can forge any JWT or Auth Verifier token.

**Pre-conditions**: KMS binary compiled with `insecure` feature. This is a build-time decision.

**Impact**: Complete authentication bypass. Any client can impersonate any user.

**Evidence**: `auth_verifier/token.rs` — `#[cfg(any(test, feature = "insecure"))]` branch uses `danger::insecure_decode`. `jwt_config.rs` — same pattern.

**Mitigations present**: `insecure` is not a default feature. Production builds use `cargo build` (FIPS mode) or `cargo build --features non-fips`, neither of which includes `insecure`.

**Gaps**: No runtime check or startup warning when `insecure` is enabled. A CI/CD misconfiguration could produce a production binary with `insecure`.

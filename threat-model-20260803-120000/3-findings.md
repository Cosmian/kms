# Security Findings — KMS Authentication Subsystem (Spire Branch)

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 5 |
| 🔵 LOW | 4 |
| ⚪ INFO | 4 |

---

## Finding Cards

### [F-001] 🔴 CRITICAL — `insecure` Feature Flag Disables All Token Signature Validation

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-287: Improper Authentication |
| **OWASP** | A07:2025 — Identification and Authentication Failures |
| **CVSS 4.0** | 9.0 — `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Component** | Auth Verifier + JWT middlewares |
| **File** | `crate/server/src/middlewares/auth_verifier/token.rs:L92`, `crate/server/src/middlewares/jwt/jwt_config.rs:L155` |

#### Description

When the KMS binary is compiled with `--features insecure`, both the Auth Verifier middleware and the standard JWT middleware skip all signature validation. The `verify_auth_verifier_jwt_subject()` function uses `danger::insecure_decode()` which decodes the JWT without verifying the signature. Similarly, `JwtConfig::validate_authentication_token()` uses the same insecure path. An attacker who can present any syntactically valid JWT (with arbitrary `sub` or `email` claims) gains full authenticated access as that identity.

#### Evidence

```rust
// auth_verifier/token.rs — insecure build path
#[cfg(any(test, feature = "insecure"))]
{
    let token_data = dangerous::insecure_decode::<AuthVerifierClaims>(token).map_err(|e| {
        KmsError::Unauthorized(format!("Auth Verifier: cannot decode token: {e}"))
    })?;
    Ok(token_data.claims.sub)
}
```

```rust
// jwt/jwt_config.rs — insecure build path
#[cfg(any(test, feature = "insecure"))]
{
    let token_data = dangerous::insecure_decode::<UserClaim>(token)
        .map_err(|e| KmsError::Unauthorized(format!("Cannot validate token: {e}")))?;
    Ok(token_data.claims)
}
```

#### Attack Scenario

1. Attacker determines the KMS binary was compiled with `insecure` feature (e.g., via error message differences or operational intelligence).
2. Attacker crafts a JWT with `{"sub": "admin", "exp": 9999999999}` and any signature (e.g., `HS256` with empty secret).
3. Attacker sends `Authorization: Bearer <forged-jwt>` to any KMS endpoint.
4. KMS decodes the token without signature verification, extracts `sub = "admin"`, and grants admin access.

**Proposed Fix** (review before applying)

Add a startup check that panics or logs a prominent warning when `insecure` is enabled in a non-test build:

```rust
#[cfg(feature = "insecure")]
{
    tracing::error!(
        "SECURITY: KMS compiled with 'insecure' feature — ALL token signature validation is \
         DISABLED. This binary MUST NOT be used in production."
    );
}
```

Consider adding a `/health` endpoint field that reports whether signature validation is active.

---

### [F-002] 🟠 HIGH — `accept_invalid_certs` Disables TLS Verification for Auth-Verifier and JWKS

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing / Information Disclosure |
| **CWE** | CWE-295: Improper Certificate Validation |
| **OWASP** | A02:2025 — Cryptographic Failures |
| **CVSS 4.0** | 7.5 — `CVSS:4.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Component** | JWKS Manager + Auth Verifier Config |
| **File** | `crate/server/src/middlewares/jwt/jwks.rs:L183`, `crate/server/src/config/command_line/auth_verifier_config.rs:L51` |

#### Description

The `auth_verifier_accept_invalid_certs` and `vault_auth_verifier_accept_invalid_certs` flags disable TLS certificate verification for outbound connections to the auth-verifier and JWKS endpoints. When enabled, a network attacker can perform MITM to inject rogue JWKS keys (enabling forged token validation) or intercept `lookup-self` responses (enabling identity spoofing for SPIRE tokens).

Both flags default to `false` and are documented as dev/test only, but they are configurable via environment variables (`KMS_AUTH_VERIFIER_ACCEPT_INVALID_CERTS`, `KMS_VAULT_AUTH_VERIFIER_ACCEPT_INVALID_CERTS`) with no runtime enforcement or health-check indicator.

#### Evidence

```rust
// jwks.rs — TLS verification bypass
let mut client = Client::builder()
    .timeout(std::time::Duration::from_secs(30))
    .redirect(reqwest::redirect::Policy::none())
    .danger_accept_invalid_certs(accept_invalid_certs);
```

```rust
// start_kms_server.rs — vault HTTP client
if kms_server.params.vault_auth_verifier_accept_invalid_certs {
    builder = builder.danger_accept_invalid_certs(true);
}
```

#### Attack Scenario

1. Operator enables `KMS_AUTH_VERIFIER_ACCEPT_INVALID_CERTS=true` for testing and forgets to disable it.
2. Attacker on the same network segment performs ARP spoofing or DNS poisoning.
3. Attacker intercepts the KMS→auth-verifier JWKS fetch and returns a JWKS containing the attacker's public key.
4. Attacker forges an Auth Verifier JWT signed with their private key.
5. KMS validates the forged JWT against the injected key → authentication bypass.

**Proposed Fix** (review before applying)

1. Add a startup warning log at `ERROR` level when `accept_invalid_certs` is true.
2. Add a `/health` or `/status` field reporting TLS verification status.
3. Consider restricting `accept_invalid_certs` to a compile-time feature flag (like `insecure`) rather than a runtime config.

---

### [F-003] 🟠 HIGH — Auth Proxy as Unauthenticated DoS Amplifier

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A05:2025 — Security Misconfiguration |
| **CVSS 4.0** | 7.5 — `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Component** | SPIRE Auth Proxy |
| **File** | `crate/server/src/routes/spire/auth_proxy.rs`, `crate/server/src/start_kms_server.rs` (scope wiring) |

#### Description

The `/v1/auth/*` scope is intentionally unauthenticated (SPIRE agents must authenticate *through* the auth-verifier). However, the proxy forwards every request to the auth-verifier without any rate limiting at the scope level. An attacker can flood the proxy with requests, overwhelming the auth-verifier and causing authentication failures for all legitimate SPIRE agents.

The global rate limiter (if configured) provides per-IP throttling, but it is disabled by default (`rate_limit_per_second: None`).

#### Evidence

The auth proxy scope in `start_kms_server.rs` has no rate limiter middleware:

```rust
// SPIRE auth proxy scope — no rate limiter
let auth_scope = web::scope("/v1/auth")
    .app_data(Data::new(vault_http_client.clone()))
    .app_data(Data::new(spire_auth_verifier_url.clone()))
    .default_service(web::to(proxy_auth_request));
```

#### Attack Scenario

1. Attacker sends 10,000 requests/second to `POST /v1/auth/approle/login` with varying source IPs (botnet).
2. The KMS proxy forwards each request to the auth-verifier.
3. Auth-verifier becomes overwhelmed; legitimate SPIRE agents receive 502 or timeouts.
4. SPIRE-managed workloads cannot authenticate → service disruption.

**Proposed Fix** (review before applying)

1. Add a dedicated rate limiter for the auth proxy scope (e.g., 50 req/s per IP).
2. Implement a circuit breaker: if auth-verifier returns 5xx for N consecutive requests, temporarily stop forwarding and return 503 directly.
3. Add request body size limits for auth proxy requests.

---

### [F-004] 🟠 HIGH — SPIRE Identity Collision with Native Usernames

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 7.0 — `CVSS:4.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Component** | SPIRE Token Middleware |
| **File** | `crate/server/src/middlewares/spire_token.rs:validated_entity()` |

#### Description

The `validated_entity()` function rejects SPIRE entity IDs that are empty or match `default_username`, but does not prevent collision with other native KMS usernames. When `vault_token_optional_middleware` is active on KMIP/MS-DKE/tokenize scopes, a SPIRE identity named "alice" receives the same `AuthenticatedUser { username: "alice" }` as a natively-authenticated "alice". The KMS permission system then grants the SPIRE token access to all objects owned by native "alice".

#### Evidence

```rust
fn validated_entity(entity_id: String, default_username: &str) -> Result<String, String> {
    if entity_id.trim().is_empty() {
        return Err("...empty entity_id...".to_owned());
    }
    if entity_id == default_username {
        return Err(format!("...collides with default_username..."));
    }
    Ok(entity_id)
}
```

Only `default_username` is checked. No namespace prefix (e.g., `spire:alice`) is applied.

#### Attack Scenario

1. Organization has a native KMS user "alice" who owns sensitive transit keys.
2. An operator creates a SPIRE AppRole named "alice" (or the auth-verifier returns `entity_id = "alice"` for a different workload).
3. The SPIRE client presents its `X-Vault-Token` to the KMIP scope.
4. `vault_token_optional_middleware` validates the token and injects `AuthenticatedUser { username: "alice" }`.
5. The SPIRE client can now access, export, or destroy native "alice"'s keys.

**Proposed Fix** (review before applying)

Prefix SPIRE identities with a namespace separator to prevent collision:

```rust
fn validated_entity(entity_id: String, default_username: &str) -> Result<String, String> {
    // ... existing checks ...
    Ok(format!("spire:{entity_id}"))
}
```

Alternatively, maintain a configurable allowlist of permitted entity IDs.

---

### [F-005] 🟡 MEDIUM — JWKS Key Material Logged on Error

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-209: Generation of Error Message Containing Sensitive Information |
| **OWASP** | A09:2025 — Security Logging and Monitoring Failures |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Component** | JWT Config |
| **File** | `crate/server/src/middlewares/jwt/jwt_config.rs:L167` |

#### Description

When a JWT `kid` is not found in the JWKS, the error message includes the full JWKS debug output:

```rust
KmsError::Unauthorized(format!(
    "Specified key not found in set. Looking for kid `{kid}` in JWKS:\n{:?}",
    self.jwks
))
```

This leaks all public keys in the JWKS to the client. While public keys are not secret by themselves, exposing the full key set aids an attacker in understanding the key infrastructure and could facilitate key confusion attacks.

#### Evidence

`jwt_config.rs` — the error message includes `{:?}` debug formatting of the entire `JwksManager`.

#### Attack Scenario

1. Attacker sends a JWT with a random `kid` to probe the JWKS.
2. Error response includes all public keys in the JWKS.
3. Attacker uses the key set to plan a key confusion or algorithm substitution attack.

**Proposed Fix** (review before applying)

Remove the JWKS debug output from the error message:

```rust
KmsError::Unauthorized(format!(
    "Specified key not found in set. Looking for kid `{kid}`"
))
```

---

### [F-006] 🟡 MEDIUM — No Audit Trail Distinguishing Auth Methods

| Field | Value |
|-------|-------|
| **STRIDE** | Repudiation |
| **CWE** | CWE-778: Insufficient Logging |
| **OWASP** | A09:2025 — Security Logging and Monitoring Failures |
| **CVSS 4.0** | 4.3 — `CVSS:4.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Component** | Auth middleware stack |
| **File** | `crate/server/src/middlewares/mod.rs:AuthenticatedUser` |

#### Description

The `AuthenticatedUser` struct contains only a `username` field. Once a request is authenticated, there is no record of *which* authentication method was used (SPIRE token, OIDC JWT, Auth Verifier JWT, API token, mTLS, or session cookie). This makes it impossible for operators to audit whether a KMIP operation was performed by a SPIRE agent or a native user with the same username.

#### Evidence

```rust
pub(crate) struct AuthenticatedUser {
    pub username: String,
    // No auth_method field
}
```

All middlewares inject the same struct type. No middleware logs the auth method at `info!` level.

#### Attack Scenario

1. A malicious SPIRE agent performs unauthorized key exports.
2. Operator investigates audit logs but cannot determine whether the requests came from the SPIRE agent or a native user with the same identity.
3. The attacker repudiates the action, claiming it was a different identity.

**Proposed Fix** (review before applying)

Add an `auth_method` field to `AuthenticatedUser`:

```rust
pub(crate) enum AuthMethod {
    SpireToken,
    OidcJwt,
    AuthVerifierJwt,
    ApiToken,
    Mtls,
    Session,
    DefaultUser,
}

pub(crate) struct AuthenticatedUser {
    pub username: String,
    pub auth_method: AuthMethod,
}
```

Log the auth method at `info!` level for each authenticated request.

---

### [F-007] 🟡 MEDIUM — `force_refresh()` Unthrottled JWKS Fetch

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A04:2025 — Insecure Design |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Component** | JWKS Manager |
| **File** | `crate/server/src/middlewares/jwt/jwks.rs:force_refresh()` |

#### Description

The `force_refresh()` method bypasses the 60-second `REFRESH_INTERVAL` throttle. It is called from `auth_verifier/token.rs` when the JWKS cache is empty. An attacker who can cause the cache to be empty (e.g., by timing requests right after a server restart when the initial fetch failed) can trigger unthrottled JWKS fetches on every request, hammering the JWKS endpoint.

#### Evidence

```rust
// auth_verifier/token.rs
let jwks = jwks_manager.find_any()?;
if jwks.is_empty() {
    jwks_manager.force_refresh().await?;
}
let jwks = jwks_manager.find_any()?;
```

The `force_refresh()` call is per-request, not globally throttled.

#### Attack Scenario

1. Attacker identifies that the JWKS cache is empty (e.g., after server restart with unreachable IdP).
2. Attacker sends many concurrent requests with Auth Verifier bearer tokens.
3. Each request triggers `force_refresh()`, sending a fetch to the JWKS endpoint.
4. The JWKS endpoint is overwhelmed or the KMS's outbound connections are exhausted.

**Proposed Fix** (review before applying)

Add a per-instance `force_refresh` cooldown (e.g., 5 seconds) using an `AtomicBool` or `Instant`:

```rust
async fn force_refresh(&self) -> KResult<()> {
    // Prevent rapid-fire force refreshes
    let mut last_force = self.last_force_refresh.write().map_err(...)?;
    if last_force.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) {
        return Ok(()); // Skip — too soon
    }
    *last_force = Some(Utc::now());
    drop(last_force);
    self.refresh_internal(true).await
}
```

---

### [F-008] 🟡 MEDIUM — Session Cookie `user_id` as Sole UI Auth

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **CWE** | CWE-331: Insufficient Entropy |
| **OWASP** | A07:2025 — Identification and Authentication Failures |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **Component** | Session Auth Middleware |
| **File** | `crate/server/src/middlewares/session_auth.rs` |

#### Description

The session auth middleware trusts the `user_id` stored in the actix-session cookie. The session is encrypted with a key derived from `ui_session_salt`. If the salt is weak, predictable, or shared across environments (e.g., dev and prod), an attacker could forge session cookies with arbitrary `user_id` values.

#### Evidence

```rust
let session = req.get_session();
match session.get::<String>("user_id") {
    Ok(Some(user_id)) => {
        req.extensions_mut()
            .insert(AuthenticatedUser { username: user_id });
    }
    // ...
}
```

The session is trusted without re-validation. No additional check (e.g., session ID against a server-side store) is performed.

#### Attack Scenario

1. Operator uses a weak `ui_session_salt` (e.g., "test" or "dev") in production.
2. Attacker determines the salt (via source code leak, config file access, or brute force).
3. Attacker forges an encrypted session cookie with `user_id = "admin"`.
4. Session auth middleware decrypts the cookie, extracts `user_id = "admin"`, and grants admin access.

**Proposed Fix** (review before applying)

1. Validate `ui_session_salt` entropy at startup (minimum 32 bytes, reject known-weak values).
2. Consider adding a server-side session store (e.g., Redis) for session revocation capability.
3. Add `HttpOnly`, `Secure`, `SameSite=Strict` flags to the session cookie (verify actix-session defaults).

---

### [F-009] 🟡 MEDIUM — Auth Proxy Forwards Authorization Header (Potential SSRF)

| Field | Value |
|-------|-------|
| **STRIDE** | Abuse |
| **CWE** | CWE-918: Server-Side Request Forgery |
| **OWASP** | A10:2025 — Server-Side Request Forgery |
| **CVSS 4.0** | 6.5 — `CVSS:4.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Component** | SPIRE Auth Proxy |
| **File** | `crate/server/src/routes/spire/auth_proxy.rs:L67` |

#### Description

The auth proxy forwards the `Authorization` header to the auth-verifier. While path traversal is blocked by `path_has_dot_segment()`, the proxy still allows arbitrary HTTP methods and query parameters. If the auth-verifier has endpoints outside `/auth/*` that accept `Authorization` headers and are reachable via the base URL, the proxy could be used to reach them.

The current path check only blocks `.` and `..` segments. It does not restrict the set of allowed paths beyond the `/v1/auth/*` prefix.

#### Evidence

```rust
for header_name in &["X-Vault-Token", "Content-Type", "Authorization"] {
    if let Some(val) = req.headers().get(*header_name) {
        if let Ok(s) = val.to_str() {
            rb = rb.header(header_name, s);
        }
    }
}
```

#### Attack Scenario

1. Auth-verifier has an admin endpoint at `/admin/users` that accepts `Authorization: Bearer <admin-token>`.
2. Attacker sends `GET /v1/admin/users` — but this is blocked because the proxy scope is `/v1/auth/*`, not `/v1/*`.
3. However, if the auth-verifier has endpoints at `/auth/admin/...` that are not intended for proxy access, the proxy would forward to them.

**Proposed Fix** (review before applying)

1. Restrict the proxy to a whitelist of allowed auth-verifier paths (e.g., `/auth/approle/*`, `/auth/token/*`).
2. Strip the `Authorization` header from proxied requests (SPIRE uses `X-Vault-Token`, not `Authorization`).

---

### [F-010] 🔵 LOW — SPIRE Token Cache Memory Bound

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A04:2025 — Insecure Design |
| **CVSS 4.0** | 4.3 — `CVSS:4.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` |
| **Component** | SpireTokenCache |
| **File** | `crate/server/src/middlewares/spire_token.rs:DEFAULT_MAX_ENTRIES` |

#### Description

The `SpireTokenCache` is bounded to 100,000 entries with opportunistic eviction of expired entries. Each entry holds a `SpireAuthenticatedUser` with a `Vec<String>` policies field. With many unique valid tokens, memory usage could grow to ~50-100MB. The eviction is opportunistic (triggered only when `max_entries` is reached), so expired entries may linger.

#### Evidence

```rust
const DEFAULT_MAX_ENTRIES: usize = 100_000;
```

#### Attack Scenario

1. Attacker with access to many valid SPIRE tokens (e.g., via compromised auth-verifier) presents unique tokens to fill the cache.
2. Legitimate tokens are evicted, causing cache misses and increased auth-verifier load.

**Proposed Fix** (review before applying)

Consider a background sweeper task that periodically evicts expired entries, rather than relying solely on opportunistic eviction.

---

### [F-011] 🔵 LOW — No Per-Entity Quota for Transit Key Creation

| Field | Value |
|-------|-------|
| **STRIDE** | Abuse |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A04:2025 — Insecure Design |
| **CVSS 4.0** | 4.3 — `CVSS:4.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` |
| **Component** | SPIRE Transit Routes |
| **File** | `crate/server/src/routes/spire/transit.rs:create_transit_key()` |

#### Description

SPIRE-authenticated users can create transit keys without any per-entity quota. A compromised SPIRE agent could create thousands of transit keys, consuming database storage and complicating key management.

#### Evidence

`transit.rs:create_transit_key()` — no quota check before creating the key pair.

#### Attack Scenario

1. Compromised SPIRE agent creates 10,000 transit keys in rapid succession.
2. Database grows; key listing becomes slow; operational overhead increases.

**Proposed Fix** (review before applying)

Add a per-entity key count limit (e.g., max 100 transit keys per entity). Check before creation.

---

### [F-012] 🔵 LOW — Auth Proxy Response Body Read Failure Returns 502

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-209: Generation of Error Message Containing Sensitive Information |
| **OWASP** | A09:2025 — Security Logging and Monitoring Failures |
| **CVSS 4.0** | 3.1 — `CVSS:4.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L` |
| **Component** | SPIRE Auth Proxy |
| **File** | `crate/server/src/routes/spire/auth_proxy.rs:L88` |

#### Description

When the auth-verifier response body read fails mid-transfer, the error message includes the internal error details:

```rust
return HttpResponse::BadGateway().json(serde_json::json!({
    "errors": [format!("auth-verifier response body read failed: {e}")]
}));
```

This leaks internal connection details to the client.

#### Evidence

Error message includes `{e}` which may contain internal hostnames, connection details, or TLS error specifics.

#### Attack Scenario

1. Attacker triggers a mid-transfer failure (e.g., by sending a large request that causes the auth-verifier to timeout).
2. Error response reveals internal auth-verifier hostname or connection details.

**Proposed Fix** (review before applying)

Return a generic error message; log the details server-side:

```rust
warn!("vault auth proxy: response body read failed: {e}");
return HttpResponse::BadGateway().json(serde_json::json!({
    "errors": ["auth-verifier response read failed"]
}));
```

---

### [F-013] 🔵 LOW — `reqwest_method` Fallback to POST

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering |
| **CWE** | CWE-477: Use of Obsolete Function |
| **OWASP** | A06:2025 — Vulnerable and Outdated Components |
| **CVSS 4.0** | 2.7 — `CVSS:4.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Component** | SPIRE Auth Proxy |
| **File** | `crate/server/src/routes/spire/auth_proxy.rs:reqwest_method()` |

#### Description

The `reqwest_method` function falls back to `POST` if `Method::from_bytes` fails. While this is documented as unreachable for actix-parsed methods, a future change in actix's method parsing could cause unexpected method substitution.

#### Evidence

```rust
fn reqwest_method(method: &str) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST)
}
```

#### Attack Scenario

Theoretical: if actix allows a non-standard method through, it would be silently converted to POST, potentially reaching a different auth-verifier endpoint than intended.

**Proposed Fix** (review before applying)

Return an error instead of silently falling back:

```rust
fn reqwest_method(method: &str) -> KResult<reqwest::Method> {
    reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| KmsError::InvalidRequest(format!("unsupported HTTP method: {e}")))
}
```

---

## Informational Findings

### [F-014] ⚪ INFO — SPIRE Token Cache Uses SHA-256 for Token Hashing

The `SpireTokenCache` hashes tokens with SHA-256 before storing them in the `DashMap`. This prevents raw token material from residing in memory. SHA-256 collision resistance (2^128) makes hash collision attacks infeasible. No action required.

### [F-015] ⚪ INFO — Algorithm Allowlist Prevents Confusion Attacks

Both JWT and Auth Verifier middlewares restrict accepted algorithms to asymmetric families (RS*, ES*, PS*). HS* algorithms are explicitly excluded, preventing the classic algorithm-confusion attack where an attacker uses the public key as an HMAC secret. Well-designed control.

### [F-016] ⚪ INFO — Redirect Policy Prevents SSRF via JWKS 3xx

The JWKS fetch uses `redirect::Policy::none()` to prevent SSRF via crafted 3xx responses from a compromised JWKS endpoint. This is a deliberate security control (referenced as A10-2 in the codebase).

### [F-017] ⚪ INFO — `validated_entity()` Prevents Default Username Collision

The `validated_entity()` function explicitly rejects entity IDs that match the KMS `default_username`, preventing SPIRE tokens from inheriting the default user's permissions. This is a deliberate security control against identity collision.

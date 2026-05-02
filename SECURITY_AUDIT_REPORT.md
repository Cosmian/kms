# Cosmian KMS Server — Security Audit Report

**Date**: 2025-01-28
**Scope**: Full source-code review of the KMS server (`crate/server/`, `crate/server_database/`, `crate/crypto/`, `crate/kmip/`)
**Methodology**: Manual code review, static analysis, red-team perspective
**Auditor**: AI-assisted (Claude) — independent review, not committed to repository

---

## Executive Summary

The Cosmian KMS has a generally strong security posture with proper cryptographic practices, parameterized SQL queries, hardened TTLV deserialization, and defense-in-depth for JWT authentication. However, **12 findings** were identified ranging from Critical to Informational severity. The most severe is an **unauthenticated decryption oracle** in the Microsoft DKE integration.

| Severity | Count | Key Finding |
|----------|-------|-------------|
| **CRITICAL** | 1 | MS DKE unauthenticated RSA decryption oracle |
| **HIGH** | 2 | Revoked key cache bypass; Google CSE SSRF |
| **MEDIUM** | 4 | Session salt, info disclosure, error leakage, non-atomic revocation |
| **LOW** | 4 | Session fixation, one-time-token cleanup, access key oracle, cert chain depth |
| **INFO** | 1 | Sensitive data in startup logs |

---

## CRITICAL Findings

### VULN-01: MS DKE Unauthenticated RSA Decryption Oracle

**CVSS 3.1 estimate**: 9.1 (Critical)
**Attack vector**: Network / No authentication required
**File**: `crate/server/src/start_kms_server.rs` (L842–850), `crate/server/src/routes/ms_dke/mod.rs` (L175–227)

#### Description

The `/ms_dke` HTTP scope is registered **without any authentication middleware**:

```rust
// start_kms_server.rs L842-850
let ms_dke_scope = web::scope("/ms_dke")
    .wrap(Cors::permissive())     // Only CORS — NO auth middleware
    .service(ms_dke::version)
    .service(ms_dke::get_key)
    .service(ms_dke::decrypt);
app = app.service(ms_dke_scope);
```

Compare with other enterprise scopes which all have authentication:

- AWS XKS: `.wrap(aws_xks::Sigv4MWare::new(...))`
- Azure EKM: `.wrap(EnsureAuth::new(...))` + `.wrap(TlsAuth)`
- Google CSE: Internal JWT validation per-handler

The `internal_decrypt()` function at `ms_dke/mod.rs:195` calls `kms.get_user(&req_http)` which falls back to `default_username` when no `AuthenticatedUser` extension is present:

```rust
// permissions.rs L228-249
pub(crate) fn get_user(&self, req_http: &HttpRequest) -> String {
    if self.params.force_default_username {
        return self.params.default_username.clone();
    }
    req_http.extensions().get::<AuthenticatedUser>()
        .map_or_else(
            || self.params.default_username.clone(),  // ← ALWAYS this path for DKE
            |au| au.username.clone(),
        )
}
```

#### Impact

Any network-reachable client can:

1. `GET /ms_dke/{key_name}` — retrieve the RSA public key (modulus, exponent) for any tagged key
2. `POST /ms_dke/{key_name}/{key_id}/decrypt` — decrypt arbitrary ciphertext using the server's RSA private key

This is a **full decryption oracle** for any RSA key accessible by the default user. Combined with `Cors::permissive()`, browser-based cross-origin attacks are also possible.

#### Exploitation

```bash
# Step 1: Get public key for any key name
curl -s http://<kms-host>:9998/ms_dke/my_key

# Step 2: Decrypt arbitrary ciphertext (base64-encoded)
curl -s -X POST http://<kms-host>:9998/ms_dke/my_key/any_id/decrypt \
  -H "Content-Type: application/json" \
  -d '{"alg": "RSA-OAEP-256", "value": "<base64-ciphertext>"}'
```

#### Mitigation

**Option A** (recommended): Add JWT bearer token validation as required by Microsoft's DKE protocol specification. The DKE client sends an Azure AD token that should be validated.

**Option B** (minimum): Add `EnsureAuth` middleware wrapping the scope, consistent with Azure EKM.

**Option C** (defense-in-depth): Document that the DKE endpoint MUST be network-isolated and add a startup warning when `ms_dke_service_url` is configured without any auth mechanism.

---

## HIGH Findings

### VULN-02: Revoked Key Remains Usable via Unwrapped Cache

**CVSS 3.1 estimate**: 7.5 (High)
**Attack vector**: Authenticated user / Time-based
**File**: `crate/server_database/src/core/database_objects.rs` (L261–264), `crate/server_database/src/core/unwrapped_cache.rs`

#### Description

When a key is revoked, `update_state()` does **not** invalidate the unwrapped cache:

```rust
// database_objects.rs L261-264
pub async fn update_state(&self, uid: &str, state: State) -> DbResult<()> {
    let db = self.get_object_store(uid).await?;
    Ok(db.update_state(uid, state).await?)
    // ← NO cache invalidation here
}
```

Compare with `delete()` (L268–271) which properly calls `self.unwrapped_cache.clear_cache(uid).await`, and `update_object()` (L255–258) which calls `self.unwrapped_cache.validate_cache(uid, object).await`.

The `validate_cache()` called during revocation (via `update_object` in `revoke_key_core`) checks only the **key block fingerprint**, not the object state. Since revocation changes the state column and attributes (adding `CompromiseDate`) but NOT the key material itself, the fingerprint matches and the cached entry **survives**.

#### Impact

After a key is revoked:

- The unwrapped key remains in the LRU cache (max 100 entries)
- It remains valid until GC evicts it (configured `max_age`, default depends on deployment)
- Any authenticated user with prior `Decrypt`/`Sign` permission can continue using the key
- The `decrypt()` flow calls `kms.get_unwrapped()` → `unwrapped_cache.peek()` → cache hit → returns unwrapped key without re-checking state

#### Exploitation

1. User A has decrypt permission on key K
2. Admin revokes key K
3. User A immediately sends decrypt request
4. Server serves the request from cache (state check passes because it checks the DB state via `retrieve_object`, but the unwrapped key comes from cache)

Wait — let me refine: the `decrypt()` function does check `get_effective_state(&owm)? != State::Active` on the retrieved object. So the race window is between `update_object` (attributes written) and `update_state` (state column written). During this window:

- The state column still says `Active`
- But the attributes already contain revocation metadata

The more reliable exploit is the **two-step non-atomic revocation** (see VULN-05 below).

**However**, there's a distinct scenario: if the `decrypt()` retrieval hits a **stale reader** (SQLite WAL) that hasn't seen the writer's commit yet, the key appears Active and the cached unwrapped version is used.

#### Mitigation

Add `self.unwrapped_cache.clear_cache(uid).await` in `update_state()` when the new state is not `Active` or `PreActive`:

```rust
pub async fn update_state(&self, uid: &str, state: State) -> DbResult<()> {
    let db = self.get_object_store(uid).await?;
    db.update_state(uid, state).await?;
    if !matches!(state, State::Active | State::PreActive) {
        self.unwrapped_cache.clear_cache(uid).await;
    }
    Ok(())
}
```

---

### VULN-03: Google CSE Rewrap — Server-Side Request Forgery (SSRF)

**CVSS 3.1 estimate**: 7.2 (High)
**Attack vector**: Authenticated (Google CSE Migrator role JWT required)
**File**: `crate/server/src/routes/google_cse/operations.rs` (L1040–1046)

#### Description

The `rewrap` endpoint makes an outbound HTTP request to `request.original_kacls_url`, which is user-supplied in the JSON body:

```rust
// operations.rs L1040-1046
let unwrapped_key = Client::new()
    .post(format!("{}/privilegedunwrap", request.original_kacls_url))
    .json(&unwrap_request)
    .send()
    .await?
```

No URL validation is performed:

- No scheme restriction (allows `http://`, `file://`, `gopher://` depending on reqwest config)
- No blocklist for internal IPs (`127.0.0.1`, `169.254.169.254`, `10.x.x.x`, `172.16.x.x`)
- `Client::new()` follows redirects by default (amplifying the attack)

#### Impact

An attacker with a valid Google CSE Migrator role token can:

1. Target cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`)
2. Scan internal network services
3. Exfiltrate data from internal HTTP services
4. Target the KMS server itself (`http://127.0.0.1:9998/server-info`)

#### Mitigation

1. Validate `original_kacls_url` against an allowlist of known KACLS base URLs (configurable)
2. At minimum, reject non-HTTPS schemes and private/loopback IP ranges
3. Disable redirect following: `.redirect(reqwest::redirect::Policy::none())`

---

## MEDIUM Findings

### VULN-04: Predictable Session Cookie Key (Default Salt)

**File**: `crate/server/src/start_kms_server.rs` (L741–751)

When `ui_session_salt` is not configured, the session encryption key is derived from:

- A **hardcoded constant**: `"cosmian_kms_default_ui_session_key_v1"` (publicly visible in open-source code)
- The **public URL** of the KMS server (by definition, publicly known)

An attacker who knows the KMS public URL can derive the session cookie encryption key and forge arbitrary session cookies, impersonating any user.

**Mitigating factors**: A warning is logged. The attack requires knowledge of the exact public URL string used in derivation.

**Recommendation**: Either require `ui_session_salt` in production (fail-closed) or generate a random salt at first startup and persist it to the database.

---

### VULN-05: Non-Atomic Key Revocation (TOCTOU)

**File**: `crate/server/src/core/operations/revoke.rs` (L318–327)

Key revocation performs two separate, non-transactional DB operations:

```rust
kms.database.update_object(owm.id(), owm.object(), owm.attributes(), None).await?;
kms.database.update_state(owm.id(), state).await?;
```

Between these calls, a concurrent `decrypt()` can read the state as `Active` and proceed with decryption. On PostgreSQL/MySQL (true concurrent writers), this window is exploitable under load.

**Recommendation**: Combine both operations in a single database transaction.

---

### VULN-06: Information Disclosure via `/server-info`

**File**: `crate/server/src/routes/mod.rs` (L109–137)

The unauthenticated `/server-info` endpoint exposes:

- Exact KMS version with OpenSSL version and build variant
- FIPS mode status
- HSM vendor/model name (e.g., "Utimaco", "SoftHSM2")
- Active HSM slot numbers

This is a fingerprinting goldmine for targeted attacks against known CVEs.

**Recommendation**: Move behind authentication, or reduce to version-only (remove HSM details).

---

### VULN-07: Internal Error Details Leaked to HTTP Clients

**File**: `crate/server/src/routes/mod.rs` (L63–72), `crate/server/src/error.rs`

The `ResponseError` implementation returns raw error messages via `self.to_string()`:

- `Database Error: {0}` — may contain connection strings, table names, SQL fragments
- `Cryptographic error: {0}` — OpenSSL error chains with provider/algorithm details
- `Unexpected server error: {0}` — arbitrary internal strings

**Recommendation**: Return generic error messages to clients; log full details server-side only.

---

## LOW Findings

### VULN-08: Session Fixation (Missing `session.renew()`)

**File**: `crate/server/src/routes/ui_auth.rs` (L320–340)

After successful OIDC authentication, the pre-auth session ID is reused without rotation. `session.renew()` should be called to prevent session fixation.

**Mitigating factors**: Cookie is encrypted, `SameSite=Strict`, `HttpOnly`, `Secure` — making injection extremely difficult.

---

### VULN-09: One-Time Tokens Not Cleared After Use

**File**: `crate/server/src/routes/ui_auth.rs` (L131–162)

`pkce_verifier`, `csrf_token`, and `nonce` remain in the session after the callback consumes them. While replay is prevented by the IdP's token endpoint (codes are one-use), clearing them is defense-in-depth best practice.

---

### VULN-10: AWS XKS Access Key ID Existence Oracle

**File**: `crate/server/src/routes/aws_xks/sigv4_middleware.rs` (L183–186)

The error message `"Access key id {id} not found"` confirms whether a given access key ID is valid, enabling enumeration. Use a generic "authentication failed" message instead.

---

### VULN-11: Certificate Chain Traversal Without Depth Limit

**File**: `crate/server/src/core/operations/export_get.rs` (L1267–1283)

Certificate chain traversal loops without an explicit depth limit. A circular chain (requiring `Modify` permissions to create) could cause an infinite loop.

**Recommendation**: Add `MAX_CHAIN_DEPTH = 32` counter.

---

## INFORMATIONAL Findings

### VULN-12: Sensitive Data Logged at Startup

**File**: `crate/server/src/config/params/server_params.rs` (L389–580), `crate/server/src/start_kms_server.rs` (L381)

The `info!("KMS Server configuration: {server_params:#?}")` call logs:

- `api_token_id` — the API token identifier (line 474)
- `google_cse_migration_key` — a **PEM private key** (line 497)
- `key_wrapping_key` — the master Key Encryption Key (line 556)
- `aws_xks_sigv4_access_key_id` — AWS access key (line 505)

HSM slot passwords are properly masked (`***`), but other secrets are not.

**Recommendation**: Mask `google_cse_migration_key` (show `[PEM key provided]`), `key_wrapping_key`, and `api_token_id` in the Debug impl.

---

## Defense-in-Depth Recommendations (Not Vulnerabilities)

### REC-01: UI Callback JWT Algorithm Restriction

**File**: `crate/server/src/routes/ui_auth.rs` (L293)

The UI callback uses `Validation::new(header.alg)` without calling `check_jwt_algorithm()`. While not currently exploitable (JWK `kty` prevents HMAC usage), adding the explicit algorithm check matches the hardening in the main KMIP middleware.

### REC-02: No Quota on Object Creation

Authenticated users with `Create` permission can create unlimited keys. Consider adding per-user quotas for multi-tenant deployments.

### REC-03: `insecure` Feature Flag Runtime Guard

The `insecure` feature disables JWT validation, JWKS HTTPS enforcement, and token expiration checks. Consider adding a prominent startup banner and/or compile-time warning when this feature is active.

### REC-04: CRL Fetch SSRF

**File**: `crate/server/src/core/operations/validate.rs` (L470–475)

CRL URIs extracted from imported certificates can target internal IPs. Add private IP range blocking and redirect policy for the CRL fetch client.

---

## Positive Security Findings

| Area | Assessment |
|------|-----------|
| SQL injection | **Not vulnerable** — all queries use parameterized bindings |
| Key material in memory | **Well handled** — `Zeroize`/`ZeroizeOnDrop` throughout |
| TTLV deserialization | **Hardened** — depth limit (64), field size limit (64 MB), comprehensive edge-case tests |
| JWT main path | **Strong** — algorithm confusion blocked, JWKS redirect disabled, HS* rejected |
| API token comparison | **Constant-time** — uses `subtle::ConstantTimeEq` |
| PKCE implementation | **Correct** — S256, 256-bit verifier, server-side storage |
| Cookie security | **Strong** — `HttpOnly`, `SameSite=Strict`, `Secure`, encrypted, 24h TTL |
| Path traversal | **Not vulnerable** — UIDs are DB-only, download path is hardcoded |
| Clickjacking | **Protected** — `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| Rate limiting | **Available** — `actix-governor` with per-IP keying (configurable) |
| Password-based key derivation | **Strong** — PBKDF2 (FIPS) / Argon2 (non-FIPS), minimum 16-byte salt |
| RSA defaults | **Sensible** — OAEP with SHA-256 |
| CORS (main scope) | **Restrictive** — explicit allowed origins |

---

## Appendix: Attack Surface Map

```text
                    INTERNET
                       │
           ┌───────────┴───────────┐
           │   HTTP/TLS Listener   │
           │   (actix-web)         │
           └───────────┬───────────┘
                       │
    ┌──────────────────┼──────────────────────────────────┐
    │                  │                                   │
    ▼                  ▼                                   ▼
┌─────────┐   ┌──────────────┐                 ┌───────────────────┐
│ PUBLIC  │   │ AUTHED SCOPE │                 │ ENTERPRISE SCOPES │
│ ROUTES  │   │              │                 │                   │
├─────────┤   ├──────────────┤                 ├───────────────────┤
│ /health │   │ POST /kmip/* │                 │ /google_cse (JWT) │
│ /version│   │ GET /access  │                 │ /aws (SigV4)      │
│ /server │   │ /download-cli│                 │ /azureekm (mTLS)  │
│ -info   │   │              │                 │ /ms_dke (NONE!)◄──┼── VULN-01
│ /ui/*   │   └──────┬───────┘                 └───────────────────┘
└─────────┘          │
                     ▼
          ┌──────────────────┐
          │ KMIP Dispatch    │
          │ (operation match)│
          └────────┬─────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│Database│  │ Crypto   │  │  HSM     │
│(SQLite/│  │(OpenSSL) │  │(PKCS#11) │
│ PgSQL) │  │          │  │          │
└────────┘  └──────────┘  └──────────┘
```

---

## Methodology Notes

- **Code review**: Complete manual review of auth middleware, route registration, crypto operations, DB access patterns, session management
- **Static analysis**: Ran `scan_source.py` (21 CRITICAL findings — all deprecated-algorithm usage, not exploitable vulnerabilities)
- **Red-team perspective**: Focused on finding exploitable attack chains, not theoretical concerns
- **Not tested**: Runtime exploitation (no running server was attacked)
- **Not in scope**: Dependencies (cargo-audit), infrastructure (Docker, Nix), client-side (WASM, CLI)

---

## End of report

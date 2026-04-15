# CHANGELOG — test/owasp

## Security

### KMIP Protocol / Parser

- **EXT2-2/A03-2**: Add recursion depth limit (`MAX_TTLV_DEPTH = 64`) to TTLV binary parser to prevent stack-overflow `DoS` via deeply-nested structures; includes unit tests.
- **EXT2-3/A03-3**: Add stack-depth limit (`MAX_XML_STACK_DEPTH = 64`) to TTLV XML deserializer to prevent `DoS` via deeply-nested XML.

### HTTP Server

- **EXT2-1/A04-1**: Reduce HTTP payload size limit from 10 GB to 64 MB (both `PayloadConfig` and `JsonConfig`) to prevent memory exhaustion `DoS`.
- **EXT2-5/A04-2**: Add rate-limiting middleware (`actix-governor`) controlled by `KMS_RATE_LIMIT_PER_SECOND` / `rate_limit_per_second` config field; disabled by default, enabling operators to prevent brute-force and `DoS` attacks.
- **A05-1/A01-1**: Replace `Cors::permissive()` on the main KMIP default scope with `Cors::default()` (same-origin only); enterprise-integration scopes (Google CSE, MS DKE, AWS XKS) intentionally retain permissive CORS as required by their integration contracts.

### Authentication

- **A07-1**: Reject symmetric JWT algorithms (HS256/HS384/HS512) via an explicit asymmetric-only allowlist (`RS*`, `ES*`, `PS*`) checked before `Validation::new(header.alg)`, and explicitly pin `validation.algorithms` to prevent confusion attacks.
- **A07-2**: Replace plain `==` API-token comparison with constant-time `subtle::ConstantTimeEq` to eliminate timing side-channel vulnerability.

### Logging / Credential Masking

- **A09-1**: Mask database URL passwords in `Display` impl of `MainDBConfig` using `mask_db_url_password()` helper (URL-parser-based, with multi-host PostgreSQL fallback).
- **A09-2**: Replace dot-only TLS P12 password masking (`replace('.', '*')`) with a proper `[****]` redaction.

### Session / Cookies

- **A07-4**: Change session cookie `SameSite` attribute from `None` to `Strict` to prevent CSRF attacks via cross-site request forgery.
- **A08-2**: Emit a startup `warn!` log when `ui_session_salt` is not configured, directing operators to set a strong random salt for production multi-node deployments.

### SSRF Prevention

- **A10-2/A10-3**: Build the `reqwest` HTTP client with `redirect::Policy::none()` in both the JWKS fetcher (`jwks.rs`) and the UI OAuth token exchange (`ui_auth.rs`) to prevent SSRF via crafted 3xx redirect chains.

### Key Zeroization

- **EXT1-1**: Change `derive_pbkdf2` and `derive_hkdf` return types from `KResult<Vec<u8>>` to `KResult<Zeroizing<Vec<u8>>>` so derived key bytes are scrubbed from memory on drop.

### Resource Limits

- **A04-3/EXT2-4**: Add `MAX_LOCATE_ITEMS = 1000` server-side cap in `locate.rs`; the effective limit is `min(client_requested_max, 1000)` so an unbounded result set can no longer be requested.

### Logging

- **A09-3**: Change `debug!` to `warn!` for all 401-unauthorized paths in `jwt_token_auth.rs` so authentication failures are visible at normal log levels.

### CORS — E2E Test Support

- **CI fix**: Add `cors_allowed_origins` field to `HttpConfig` (env `KMS_CORS_ALLOWED_ORIGINS`, comma-separated) so the UI E2E test KMS instance can allow the Vite dev server origin (`http://127.0.0.1:5173`) without enabling permissive CORS in production.
- **CI fix**: `Cors::default()` in actix-cors 0.6.5 starts with empty `allowed_methods` and `allowed_headers`, causing all CORS preflight method checks to fail even when an explicit origin is listed. Added `.allow_any_method().allow_any_header()` to the CORS builder when `cors_allowed_origins` is non-empty.
- **CI fix (Windows)**: The Windows PowerShell UI E2E test script was starting the KMS without `--cors-allowed-origins`, causing identical `TypeError: Failed to fetch` failures in Chromium. Moved the Vite preview port selection before KMS startup and pass the origin to the KMS via `--cors-allowed-origins`.

### Audit

- Update `scripts/audit.sh` CORS check to distinguish enterprise-integration scopes (WARN) from main KMIP scope (FAIL), and add JWT algorithm allowlist check that verifies `validation.algorithms` assignment.
- Add checks 15–19 for: `SameSite::Strict`, JWT log level (`warn!`), reqwest redirect disable, session key salt warning, and `MAX_LOCATE_ITEMS` constant.
- Add `update_audit_md()` function that automatically updates the Remediation Priority Matrix in `audit.md` from `Open` to `✅ Fixed` / `⚠️ Mitigated` based on check results.
- Update `audit.md` Remediation Priority Matrix: all High and most Medium findings now marked `✅ Fixed` or `⚠️ Mitigated`.

## Testing

### KMIP Protocol Tests

- Add 25 TTLV binary wire edge-case unit tests (W1–W25): truncated payloads, invalid header fields, structure-length underflow, depth-limit enforcement, oversized-length declarations, type-specific length checks, and round-trips (`crate/kmip/src/ttlv/tests/wire_edge_cases.rs`).
- Add 18 TTLV XML edge-case unit tests (X1–X18): malformed/empty XML, depth limits, invalid type attributes, XXE entity regression guard, Unicode/null in strings, and full round-trip (`crate/kmip/src/ttlv/tests/xml_edge_cases.rs`).
- Fix usize underflow bug in `TTLVBytesDeserializer`: `remaining -= item_length` replaced with `checked_sub` to prevent wrapping on malformed child-length fields.

### CLI Security Tests

- Add 15 adversarial HTTP wire-payload tests (S1–S15): empty, truncated, garbage, and deeply-nested TTLV, malformed JSON, and 1 MB random binary (`serialization/wire_payloads.rs`).
- Add 8 KMIP batch-protocol abuse tests (B1–B8): batch-count mismatch, zero-count, 100-item batch, and empty batch (`serialization/batch_abuse.rs`).
- Add M1–M5 memory-allocation guard tests: creating keys with sizes < 8 bits or > 8192 bits now returns a clean `InvalidRequest` error instead of allocating gigabytes of memory (`oom/large_payloads.rs`).
- Add P1–P6 cross-user privilege-escalation tests using the cert-auth server (`security/access_control.rs`).
- Add L1–L12 key lifecycle confusion tests (`security/lifecycle.rs`).
- Add U1–U9 UID injection tests (SQL injection, path traversal, information-oracle checks) (`security/uid_injection.rs`).

### Server — Resource Limit Fix

- **DoS/Memory exhaustion fix**: Add symmetric key size bounds validation in `create_symmetric_key_and_tags`: reject any request with `cryptographic_length < 8` or `> 8192` bits with `InvalidRequest` to prevent 128 MB+ key-material allocation attacks. `THREE_DES` retains its existing exact-value validation (112 or 168 bits).

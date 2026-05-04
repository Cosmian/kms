## Features

### HSM support on Linux aarch64

- Extend HSM support to Linux aarch64 (ARM64): softhsm2, smartcardhsm, and the generic `other` model now compile and run on ARM64 Linux, enabling use with hardware like Zymkey on Raspberry Pi. Proprietary HSMs (Proteccio, Utimaco, Crypt2pay) remain x86_64-only due to vendor library constraints ([#902](https://github.com/Cosmian/kms/issues/902))

### Docker CORS defaults

- Set default `KMS_CORS_ALLOWED_ORIGINS` in the Docker image to allow the bundled Web UI to work out-of-the-box without extra environment variables. Covers `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`, and `[::]` on port 9998 ([#926](https://github.com/Cosmian/kms/issues/926))

## Security

### Integer overflow checks in release builds

- Enable `overflow-checks = true` in `[profile.release]` so integer overflows panic instead of silently wrapping in production (ANSSI LANG-ARITH compliance) ([#921](https://github.com/Cosmian/kms/issues/921))

### OTLP telemetry TLS enforcement

- Reject plaintext HTTP OTLP endpoints by default to prevent encryption query metadata leaking over unencrypted channels. Add `--otlp-allow-insecure` / `KMS_OTLP_ALLOW_INSECURE` flag for explicit opt-in in development environments

### Log sanitization

- Remove sensitive cryptographic material (plaintext, ciphertext, key bytes, HMAC values, hash data) from tracing `span` fields across all KMIP operations (encrypt, decrypt, hash, MAC, import, wrap/unwrap) to prevent accidental exposure in logs

### Vulnerability disclosure

- Rewrite `SECURITY.md` with a comprehensive vulnerability disclosure list (17 entries from version 5.0.0 onward) following OpenSSL-style format with severity ratings, affected ranges, and mitigation guidance

### Hardening fixes (VULN-01 to VULN-12)

- **VULN-01**: Wrap MS DKE scope with full authentication middleware (EnsureAuth + JWT + TLS + API token) — previously unauthenticated ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-02**: Clear unwrap cache on key revocation/destruction to prevent stale key material from being used after state transitions ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-03**: Add SSRF validation on Google CSE `original_kacls_url` — reject non-HTTPS, private IPs, and internal hostnames ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-04**: Derive session salt from private server-side configuration (DB params + public URL) instead of a hardcoded default, preventing cookie forgery while remaining stable across restarts and load-balanced instances ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-05**: Use `AtomicOperation` in Activate and Revoke to prevent TOCTOU race conditions between object update and state change ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-06**: Move `/server-info` endpoint behind authentication middleware ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-07**: Return generic "Internal server error" for 5xx responses instead of leaking internal error details ([#928](https://github.com/Cosmian/kms/pull/928))
- **VULN-12**: Mask sensitive fields (`api_token_id`, `google_cse_migration_key`, `key_wrapping_key`) in `ServerParams` Debug output ([#928](https://github.com/Cosmian/kms/pull/928))

## Bug Fixes

### Server concurrency under high load

- Fix server crash/hang under concurrent AWS XKS benchmarks (16 clients, 4 CPUs) caused by tracing `span.enter()` used across `.await` boundaries — replaced all 31 occurrences in KMIP operations with `tracing::Instrument` to prevent unbounded span nesting and memory growth
- Fix `delete_attribute` tracing span incorrectly named `"encrypt"` instead of `"delete_attribute"`

### Unwrapped key cache performance

- Optimize cache fingerprint computation: serialize only the `KeyBlock` instead of the entire KMIP `Object` to TTLV, significantly reducing CPU usage on cache hit/miss paths
- Eliminate sequential write lock contention in cache `insert()` by using the existing mpsc channel for timestamp updates instead of acquiring a second `RwLock`

### SQLite backend concurrency

- Implement read/write connection split for SQLite: dedicated writer connection + pool of reader connections (default: 2×CPU cores, capped at 10) leveraging WAL mode concurrent read support
- Honor the previously ignored `max_connections` parameter for SQLite backends

## Build

### Dependency updates

- Bump `rand` from 0.9 to 0.10 and migrate API: `TryRngCore` → `TryRng`, `OsRng` → `SysRng`, `RngCore` → `Rng`
- Bump `actix-http` from 3.10 to 3.12

## Testing

### Security non-regression tests

- Add 4 security non-regression tests validating that sensitive data (plaintext, ciphertext, hash data, HMAC values) never appears in tracing span fields during encrypt, decrypt, hash, and MAC operations

### KMIP compliance tables

- Fix KMIP documentation generator to produce markdownlint-compliant output (blank lines after headings and before tables)
- Update KMIP version-aware operation tables with corrected `N/A` entries for operations not defined in earlier KMIP versions

Closes #902
Closes #921
Closes #926

### HSM Locate Name filter bypass (issue #935)

- **VULN-13**: Fix HSM Locate leaking internal KEK when a `Name` attribute filter was provided — the filter was silently ignored for HSM keys, so `ObjectType=SymmetricKey` + `Name=<anything>` matched the server KEK even for non-HSM-admin users. `Name` (and `ApplicationSpecificInformation`) are now treated as unsupported HSM attributes: a Locate with such filters returns zero HSM results, matching KMIP semantics (no HSM key has a KMIP Name, therefore none can match). ([#935](https://github.com/Cosmian/kms/issues/935))

### OIDC/PKCE regression: session cookie SameSite=Strict breaks Auth0 redirect

- Fix regression introduced in 5.21.0 (A07-4): `SameSite=Strict` on the session cookie caused `"Missing PKCE verifier"` errors after the Auth0 redirect because browsers do not send `Strict` cookies on cross-site top-level navigations (RFC 6265bis). Downgraded to `SameSite=Lax`, which is the correct setting for OIDC applications: Lax permits the session cookie on top-level GET navigations (the redirect back from the IdP) while still blocking third-party POST/AJAX CSRF vectors.

### AWS XKS single-threading bottleneck under high concurrency

- Fix AWS XKS handler bottleneck where a single CPU core was saturated under concurrent load due to `sigv4_verify()` — an HMAC-SHA256 computation over the full ~85 KB XKS request body — running synchronously on a tokio worker thread, preventing new connection acceptance. Moved to `tokio::task::spawn_blocking` so the CPU-bound work runs on the blocking thread pool and the async runtime stays free.
- Fix all PKCS#11 FFI operations in `BaseHsm` (`create_key`, `create_keypair`, `export`, `delete`, `find`, `encrypt`, `decrypt`, `sign`, `get_key_type`, `get_key_metadata`, `generate_random`, `seed_random`) being called directly on tokio async threads, blocking the entire runtime on HSM I/O. All operations now run via `tokio::task::spawn_blocking`.

### PR review fixes (Copilot + tbrezot)

- `api_token_id` in `ServerParams` debug output now shows the actual UUID value instead of `"[configured]"` — the UID is not sensitive (it is not the token secret)
- Session cookie key fallback: when `ui_session_salt` is not configured, the server now generates a cryptographically random 64-byte ephemeral key via `openssl::rand::rand_bytes` instead of deriving from configuration data (which could be public-only for SQLite deployments). Sessions are invalidated on restart in the unconfigured case; operators must set `ui_session_salt` for persistent/load-balanced sessions
- `UnwrappedCache::fingerprint()` reverted to serialize the full `Object` (not just `KeyBlock`) to preserve the original integrity guarantee across all object fields
- Removed unnecessary `validate_cache` calls from `Database::update_object`, `Database::create`, and the `Create`/`UpdateObject`/`Upsert` arms of `Database::atomic`. Key material is immutable in KMIP; the GC handles stale cache entries. Only state-transition `clear_cache` calls (revoke/destroy) are retained
- Usage limits enforcement and decrement in `encrypt.rs` now handles all four `UsageLimitsUnit` variants (`Byte`, `Object`, `Block`, `Operation`). Decrement operates directly on `owm.attributes_mut()` without the previous copy-back through `unwrapped_owm`

### AWS XKS `KMSInvalidStateException` under concurrent load

- Fix a bug where unhandled error variants in the XKS `encrypt` and `decrypt` handlers fell into a `_` catch-all that returned `HttpResponse::from_error(KmsError)`, producing HTTP 422/500 responses with `text/html` bodies instead of the XKS JSON format required by the spec. AWS KMS could not parse these responses and surfaced them as `KMSInvalidStateException`. All `KmsError` variants are now explicitly mapped to the appropriate `XksErrorReply`: `Wrong_Key_Lifecycle_State` → `InvalidStateException`, `Permission_Denied` → `InvalidKeyUsageException`, `Item_Not_Found` → `KeyNotFoundException`, `Operation_Not_Supported` → `UnsupportedOperationException`, all other validation errors → `ValidationException`, and any remaining error → `InternalException` (with server-side logging).

Closes #935

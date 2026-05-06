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

### PKCS#12 generation in FIPS mode

- Make client PKCS#12 bundle generation macOS-only: PKCS12KDF is not available under the OpenSSL FIPS provider, so P12 generation is skipped on Linux/Windows where PEM files suffice for client certificate authentication ([#928](https://github.com/Cosmian/kms/pull/928))

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

### HSM Locate Name filter bypass (issue #935)

- **VULN-13**: Fix HSM Locate leaking internal KEK when a `Name` attribute filter was provided — the filter was silently ignored for HSM keys, so `ObjectType=SymmetricKey` + `Name=<anything>` matched the server KEK even for non-HSM-admin users. `Name` (and `ApplicationSpecificInformation`) are now treated as unsupported HSM attributes: a Locate with such filters returns zero HSM results, matching KMIP semantics (no HSM key has a KMIP Name, therefore none can match). ([#935](https://github.com/Cosmian/kms/issues/935))

### OIDC/PKCE regression: session cookie SameSite=Strict breaks Auth0 redirect

- Fix regression introduced in 5.21.0 (A07-4): `SameSite=Strict` on the session cookie caused `"Missing PKCE verifier"` errors after the Auth0 redirect because browsers do not send `Strict` cookies on cross-site top-level navigations (RFC 6265bis). Downgraded to `SameSite=Lax`, which is the correct setting for OIDC applications: Lax permits the session cookie on top-level GET navigations (the redirect back from the IdP) while still blocking third-party POST/AJAX CSRF vectors.

### AWS XKS single-threading bottleneck under high concurrency

- Fix AWS XKS handler bottleneck where a single CPU core was saturated under concurrent load due to `sigv4_verify()` — an HMAC-SHA256 computation over the full ~85 KB XKS request body — running synchronously on a tokio worker thread, preventing new connection acceptance. Moved to `tokio::task::spawn_blocking` so the CPU-bound work runs on the blocking thread pool and the async runtime stays free.
- Fix all PKCS#11 FFI operations in `BaseHsm` (`create_key`, `create_keypair`, `export`, `delete`, `find`, `encrypt`, `decrypt`, `sign`, `get_key_type`, `get_key_metadata`, `generate_random`, `seed_random`) being called directly on tokio async threads, blocking the entire runtime on HSM I/O. All operations now run via `tokio::task::spawn_blocking`.

Closes #902
Closes #921
Closes #926

### Race condition in `test_privileged_users` test

- Fix intermittent `test_privileged_users` failure caused by a shared `OnceCell` (`ONCE_SERVER_WITH_PRIVILEGED_USERS`) being initialized by `privilege_bypass` tests (which register only the owner) before `test_privileged_users` could populate it with both the owner and `user.privileged@acme.com`. Added a dedicated `ONCE_SERVER_WITH_MULTI_PRIVILEGED_USERS` cell and `start_default_test_kms_server_with_multi_privileged_users()` function to isolate the two test server instances.

### PKCS#11 loader `ensure_cdylib` feature forwarding

- Fix `ensure_cdylib()` in `crate/clients/pkcs11/loader/src/tests.rs` always building with `--features non-fips` regardless of the active test profile. Now mirrors `ensure_binary.rs`: forwards `--features non-fips` only when the `non-fips` feature is active in the current compilation unit, and forwards `--release` when `debug_assertions` are disabled.

Closes #935

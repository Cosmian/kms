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

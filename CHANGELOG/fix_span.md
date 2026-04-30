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

## Documentation

### Security vulnerabilities disclosure

- Rewrite `SECURITY.md` with a comprehensive vulnerability disclosure list (18 entries from version 5.0.0 onward) following OpenSSL-style format with severity ratings, affected ranges, and mitigation guidance

Closes #902
Closes #921
Closes #926

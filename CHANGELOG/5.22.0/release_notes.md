# 5.22.0 release notes (full text)

Full text of the `## [5.22.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.22.0] - 2026-05-06

### 🚀 Features

- **HSM Linux aarch64**: extend HSM support (softhsm2, smartcardhsm, `other` model) to Linux aarch64; proprietary HSMs (Proteccio, Utimaco, Crypt2Pay) remain x86_64-only ([#902](https://github.com/Cosmian/kms/issues/902))
- **Docker CORS defaults**: set default `KMS_CORS_ALLOWED_ORIGINS` in the Docker image so the bundled Web UI works out-of-the-box on localhost/`::1`/`0.0.0.0` port 9998 ([#926](https://github.com/Cosmian/kms/issues/926))

### 🔒 Security

- **Integer overflow checks**: enable `overflow-checks = true` in `[profile.release]` (ANSSI LANG-ARITH compliance) ([#921](https://github.com/Cosmian/kms/issues/921))
- **OTLP TLS enforcement**: reject plaintext HTTP OTLP endpoints by default; add `--otlp-allow-insecure` flag for explicit dev opt-in
- **Log sanitization**: remove sensitive cryptographic material (plaintext, ciphertext, key bytes, HMAC values, hash data) from tracing span fields across all KMIP operations
- **SECURITY.md**: rewrite with 17-entry vulnerability disclosure list (5.0.0 onward), OpenSSL-style format with severity ratings
- **Hardening fixes** ([#928](https://github.com/Cosmian/kms/pull/928)):
    - **VULN-01**: wrap MS DKE scope with full authentication middleware (previously unauthenticated)
    - **VULN-02**: clear unwrap cache on key revocation/destruction
    - **VULN-03**: add SSRF validation on Google CSE `original_kacls_url`
    - **VULN-04**: derive session salt from private server-side config instead of hardcoded default
    - **VULN-05**: use `AtomicOperation` in Activate/Revoke to prevent TOCTOU races
    - **VULN-06**: move `/server-info` behind authentication middleware
    - **VULN-07**: return generic "Internal server error" for 5xx responses
    - **VULN-12**: mask sensitive fields in `ServerParams` Debug output
    - **VULN-13**: fix HSM Locate leaking internal KEK when a `Name` filter was provided — `Name`/`ApplicationSpecificInformation` filters now return zero HSM results ([#935](https://github.com/Cosmian/kms/issues/935))

### 🐛 Bug Fixes

#### KMIP Interoperability

- **FortiGate / KMIP 1.0–1.4**: fix `Authentication` deserialization to correctly handle the `Authentication { Credential { CredentialType, CredentialValue } }` nesting; fix `Locate` name filter silently dropped for KMIP 1.0/1.1 clients (FortiGate wraps filter `Attribute` items in `TemplateAttribute`) ([#824](https://github.com/Cosmian/kms/issues/824))

#### HSM

- **Sensitive (non-extractable) keys**: fix `ModifyAttribute` failing for non-extractable HSM keys — fall back to `get_key_metadata()` stub for attribute-only operations ([#933](https://github.com/Cosmian/kms/issues/933))

#### Server Concurrency & Performance

- **Span-across-await crash**: fix server crash/hang under concurrent load caused by `span.enter()` across `.await` boundaries — replaced all 31 occurrences in KMIP operations with `tracing::Instrument`
- **AWS XKS bottleneck**: move `sigv4_verify()` (HMAC-SHA256 over ~85 KB body) to `spawn_blocking`; move all PKCS#11 FFI operations in `BaseHsm` to `spawn_blocking` to unblock the async runtime
- **Unwrap cache**: optimize fingerprint by serializing `KeyBlock` only; eliminate sequential write-lock contention via existing mpsc channel
- **SQLite concurrency**: implement read/write connection split (dedicated writer + reader pool, default 2×CPU capped at 10) leveraging WAL mode; honor previously ignored `max_connections`

#### Auth / Session

- **OIDC/PKCE `SameSite` regression**: downgrade session cookie from `SameSite=Strict` to `SameSite=Lax` — `Strict` blocked the IdP redirect-back cookie, causing "Missing PKCE verifier" errors
- **PKCS#12 in FIPS mode**: skip P12 generation on Linux/Windows where the FIPS provider lacks `PKCS12KDF`; PEM files are used instead ([#928](https://github.com/Cosmian/kms/pull/928))

#### Miscellaneous

- Fix `cargo fmt` issue in `session_impl.rs`; remove unused `cosmian_logger` dev-dependency from `crypt2pay_pkcs11_loader`
- Fix `delete_attribute` tracing span incorrectly named `"encrypt"`

### 🧪 Testing

- Add 4 security non-regression tests validating sensitive data never appears in tracing span fields (encrypt, decrypt, hash, MAC)
- Add KMIP 1.2 protocol test vector for issue #933 (sensitive HSM key `ModifyAttribute`)
- Add integration test for issue #935 (`Locate` + `Name` filter does not leak the server KEK)
- Fix intermittent `test_privileged_users` race via dedicated `ONCE_SERVER_WITH_MULTI_PRIVILEGED_USERS` cell
- Fix KMIP documentation generator to produce markdownlint-compliant output

### 🔧 Build

- Bump `rand` 0.9 → 0.10 (migrate `TryRngCore`/`OsRng`/`RngCore` API); bump `actix-http` 3.10 → 3.12

### ⚙️ CI

- **Crypt2Pay**: make CI resilient to `prepare_crypt2pay.sh` self-test failures; strip `route-nopull` from OpenVPN config; add TCP connectivity check (30 retries); fix CA installation path, HSM port (3001), and bridge CA for old issuer DN; clean up stale `tun0` interface before OpenVPN start

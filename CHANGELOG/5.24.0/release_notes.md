# 5.24.0 release notes (full text)

Full text of the `## [5.24.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.24.0] - 2026-06-18

### 🔒 Security

- **COSMIAN-2026-019** (Low): Upgrade `mysql_async` 0.36→0.37 to remove `proc-macro-error2` (RUSTSEC-2026-0173)

### 🚀 Features

#### JOSE / REST Crypto API

- Support JWK import via `POST /v1/crypto/keys` for symmetric (`oct`), EC (P-256/384/521), RSA, and OKP (Ed25519) key types ([#979](https://github.com/Cosmian/kms/pull/979))
- Add `POST /v1/crypto/keys/unwrap` endpoint for RSA-OAEP CEK unwrapping without key exposure
- Allow `SignatureVerify` on private keys; `RSA-OAEP encrypt` with imported private keys ([#979](https://github.com/Cosmian/kms/pull/979))
- Accept HMAC keys longer than minimum required size (per RFC 7518 §3.2) ([#979](https://github.com/Cosmian/kms/pull/979))

#### OpenTelemetry Metrics

- Add 9 OTLP metrics: `kms.database.operations.total`, `kms.database.operation.duration`, `kms.http.requests.total`, `kms.http.request.duration`, `kms.active.connections`, `kms.objects.total`, `kms.keys.active.count`, `kms.cache.operations.total`, `kms.hsm.operations.total` ([#975](https://github.com/Cosmian/kms/pull/975))
- Redis backends use O(1) counter keys; 30-second cron sync + 5-minute reconcile for drift correction
- `OtelHttpMetrics` middleware measures true client-perceived latency with low-cardinality path labels

#### Windows / CNG KSP / Intune

- Implement Windows Service Control Manager (SCM) integration with graceful shutdown ([#924](https://github.com/Cosmian/kms/pull/924))
- Implement `Export-IntunePrivateKey` (PKCS#8 DER) and `Import-IntunePrivateKey` (PEM/DER/CNG) for Intune PFX workflows ([#924](https://github.com/Cosmian/kms/pull/924))
- Add `ckms cng verify --dll <path>` and `ckms pkcs11 verify --dll <path>` (replace standalone binaries); bundle `cosmian_cng.dll` in NSIS installer ([#924](https://github.com/Cosmian/kms/pull/924))
- Query `vendor_identification` dynamically via KMIP `Query` instead of hardcoding in CNG KSP and PKCS#11 ([#924](https://github.com/Cosmian/kms/pull/924))
- Grant default key usages for PrivateKey/PublicKey ([#1011](https://github.com/Cosmian/kms/pull/1011))

#### CKMS CLI

- Replace `reqwest` with `hyper + hyper-openssl`, enabling PQC (ML-DSA-44) TLS connections ([#1015](https://github.com/Cosmian/kms/pull/1015))
- Add `ckms activate` subcommand to all key/certificate/secret-data/opaque-object modules

#### PKCS#11 / VeraCrypt

- Expose KMS symmetric keys tagged `disk-encryption` as `CKO_DATA` token objects for VeraCrypt; configurable via `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG`
- Fix `batch_get` not returning tags: add explicit `GetAttributes(tags)` call to populate `CKO_DATA` labels

#### EDB PostgreSQL TDE

- Add EDB PostgreSQL Advanced Server TDE integration with `pykmip` and `thales` KMIP variants

#### Server Configuration

- Log OpenSSL CPU hardware-acceleration flags (AES-NI, AVX, SHA, VAES, RDRAND) at startup ([#963](https://github.com/Cosmian/kms/pull/963))
- Add secret management for KMS config files (`secret://` URIs for AWS/Azure/Vault/KMS backends) ([#932](https://github.com/Cosmian/kms/pull/932))

### 🐛 Bug Fixes

#### VAST Data / KMIP 1.4

- Fix `GetAttributes` silently dropping all vendor attributes (including `OperationPolicyName`) for KMIP 1.4 default all-attributes requests
- Fix `AddAttribute(OperationPolicyName)` dropped; now stored and returned as VendorAttribute
- Allow KMIP 1.x `vendor_identification="KMIP1"` attributes to be overwritten via `AddAttribute`

#### CKMS CLI

- Translate IANA TLS 1.2 cipher suite names to OpenSSL format; skip unknown ciphers ([#1015](https://github.com/Cosmian/kms/pull/1015))
- Use `kind="raw-dylib"` for BCrypt link to bypass `reqwest`/`ring` import-library conflicts ([#1015](https://github.com/Cosmian/kms/pull/1015))

#### HSM

- Fix `C_Finalize` forwarding to real HSM library causing `CKR_DEVICE_REMOVED` on subsequent sessions ([#924](https://github.com/Cosmian/kms/pull/924))

#### KMIP / XML

- Fix TTLV XML deserializer: handle explicit `type="Structure"` on self-closing elements
- Fix XML response comparison: `result_reason` in v1.4, `KeyMaterial::ByteString` empty match, `response_payload` presence mismatch
- Fix vector runner for MariaDB/Percona using hardcoded MySQL URL

### ♻️ Refactor

- Consolidate `ActivateKeyAction` into shared struct across 8 CLI modules; extract shared encrypt/decrypt, wrap/unwrap, derive-key, and HTTP client helpers (`apply_default_headers`, `process_error_response`, `send_ttlv_request`)
- Eliminate ~9,100 LOC duplicate tests from `cosmian_kms_cli_actions`; unify KMIP XML 1.4/2.1 test infrastructure with shared macros

### 🧪 Testing

- Add FPE E2E Playwright tests (key creation, encrypt/decrypt roundtrip, tweak validation, integer/float types)
- Add anonymization E2E tests (Argon2 hash, Laplace/Uniform/Gaussian noise, aggregate number/date)
- Add FortiGate KMIP 1.0 credential/locate non-regression vectors ([#824](https://github.com/Cosmian/kms/issues/824))
- Add JOSE interoperability suite with Python `jwcrypto` (directions A/B/C)
- Add EDB TDE integration vectors (pykmip, thales, key rotation)
- Add InterSystems IRIS mTLS integration test: KMS as external TLS key-store, `%SYSTEM.Security.SSLConfigs` client auth, full KMIP get/locate/destroy roundtrip ([#965](https://github.com/Cosmian/kms/pull/965))
- Add VeraCrypt PKCS#11 integration tests (`pkcs11-tool` discovery, volume create/mount)
- Add CNG KSP end-to-end integration in `test_windows.yml`
- Port KMIP activate lifecycle, access control, privilege bypass, and UID injection tests to `ckms` binary level

### ⚙️ Build

- Adopt **MISE** task runner: 52 tasks + 7 shared libraries under `.mise/`; migrate all automation from `.github/scripts/` ([#1001](https://github.com/Cosmian/kms/pull/1001))
- Pin `rust-overlay` URL with SHA-256 in `shell.nix`; fix Windows vcpkg manifest-mode paths
- Fix Nix `.crate` source unpacking (`builtins.fetchTarball` → `pkgs.fetchurl`)
- Fix AWS SSM parameter name collision between concurrent CI runs ([#1015](https://github.com/Cosmian/kms/pull/1015))
- Add `test-cng-ksp` job to `test_windows.yml` ([#924](https://github.com/Cosmian/kms/pull/924))
- Skip Docker startup for test types that don't require a running backend
- *(deps-dev)* Bump vite ([#1012](https://github.com/Cosmian/kms/pull/1012))

### 📚 Documentation

- Add EDB PostgreSQL TDE integration guide
- Add InterSystems IRIS integration guide: architecture, mTLS configuration, `%SYSTEM.Security.SSLConfigs` setup, and KMIP operation reference ([#965](https://github.com/Cosmian/kms/pull/965))
- Add data anonymization/tokenization guide with JSON examples
- Add Intune PFX import workflow and Mermaid architecture diagrams to CNG KSP page
- Regroup JOSE docs; add `POST /v1/crypto/keys/unwrap` endpoint reference
- Update VAST Data integration docs (OPN troubleshooting, verified-date update)
- Add tokenize endpoints to OpenAPI specification ([#907](https://github.com/Cosmian/kms/pull/907))
- Fix CLI flag, AWS SSM note, and ckms command in secret-backends docs ([#1017](https://github.com/Cosmian/kms/pull/1017))

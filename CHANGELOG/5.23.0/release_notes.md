# 5.23.0 release notes (full text)

Full text of the `## [5.23.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.23.0] - 2026-06-05

### 🚀 Features

- Support FPE and add anonymization endpoints (#907)
- Intune (#924)
- *(jwe)* Add endpoint to import wrapped key (#977)
- *(packager)* Add cosmian_kms and ckms to PATH
- Add JOSE import key endpoint (#979)
- Display OpenSSL CPU hardware-acceleration feature flags at startup (#963)

### 🐛 Bug Fixes

- *(server)* Default logging to /var/log
- *(server)* Set logging default to None

### 🚜 Refactor

- Remove duplicated clap tests in favor of ckms tests (#972)

### 🧪 Testing

- Add fortigate tests (#976)
- Add JOSE interoperability tests with jwcrypto lib (#984)

### ⚙️ Build

- Merge release/5.23.0 into develop
- *(deps-dev)* Bump vitest (#978)

### ⚙️ Miscellaneous Tasks

- Use dedicated git submodule for KMIP specs (#980)
- Add queue:max as concurrency arg

## [5.23.0] - 2026-05-25

### 🚀 Features

#### REST Crypto API (JOSE/JWE)

- New REST API under `/v1/crypto` — JOSE-compatible encrypt, decrypt, sign, verify, and MAC without a KMIP client library (RFC 7515/7516/7518) ([#868](https://github.com/Cosmian/kms/issues/868))
- Key management: `POST /v1/crypto/keys` (symmetric, RSA, EC), `DELETE /v1/crypto/keys/{kid}` with cascade destroy
- Encryption/decryption: AES-GCM direct and RSA-OAEP/RSA-OAEP-256 key wrapping with `A128/192/256GCM`; AAD binding
- Signing/verification: RS256/384/512, PS256/384/512, ES256/384/512; HMAC compute and verify (HS256/384/512)
- JOSE algorithm fields replaced with `JoseAlgorithm`/`JoseEncAlgorithm` enums — invalid values rejected at deserialization (400)

#### Multi-HSM Support

- `[[hsm_instances]]` TOML array-of-tables for simultaneous multiple HSM instances; prefix-based routing (`hsm::<model>::<slot>::<key>`) ([#942](https://github.com/Cosmian/kms/pull/942))
- `GET /hsm/status` endpoint (auth required) returning JSON array of all connected HSM instances with per-slot info
- Web UI — new `Objects → HSM Status` page; `Locate.tsx` updated to handle all multi-HSM UID prefix patterns
- HSM keys now default to `sensitive=true`; `Destroy`/`Revoke` restricted to HSM admins; `Get`-as-wildcard removed for HSM keys

#### PQC X.509 Certificates

- `Certify` supports ML-DSA-44/65/87 and all SLH-DSA variants as subject key and issuer signing algorithms (non-FIPS) ([#943](https://github.com/Cosmian/kms/pull/943))
- ML-KEM-512/768/1024 CA-issued X.509 certificates (RFC 9935); RFC 9881/9909 critical `keyUsage` auto-added for PQC certs
- `id-ce-noRevAvail` (RFC 9608, OID 2.5.29.56) auto-added to self-signed certs with no CRL DP; `authorityInfoAccess` (AIA) extension support fixed
- `Certify` split into dedicated RFC submodules (`rfc9881.rs`, `rfc9909.rs`, `rfc9935.rs`, `rfc9608.rs`)

#### ReKeyKeyPair

- `ReKeyKeyPair` (KMIP §6.1.47): implemented for RSA, EC, Ed25519, X25519, ML-KEM/ML-DSA/SLH-DSA; shared lifecycle logic in `rekey_common.rs`; KMIP 1.4 wire-format support added ([#845](https://github.com/Cosmian/kms/issues/845))

#### OpenAPI / Swagger UI

- New `/openapi.yaml` endpoint serving the OpenAPI 3.1 spec, embedded at compile time; new `/swagger` endpoint with locally-vendored Swagger UI (swagger-ui-dist 5.18.2), no CDN dependency, strict CSP header, and relative server URL for correct origin binding

#### Rebranding (Cosmian → Eviden)

- Web UI: increased Eviden logo height, orange logo in dark mode, new `E`-letter favicon (`eviden-favicon.svg`)
- Documentation: replaced all "Cosmian VM" / "Cosmian VM KMS" references with "Eviden VM" / "Eviden VM KMS"

### 🔒 Security

- **COSMIAN-2026-016** — KEK wrapping bypass: `ModifyAttribute`/`SetAttribute`/`AddAttribute`/`Activate` auto-unwrapped KEK-wrapped keys and persisted plaintext back to DB; fixed by skipping unwrap for attribute-only operations ([#960](https://github.com/Cosmian/kms/issues/960))
- **COSMIAN-2026-015** — KEK plaintext leak via UsageLimits: `decrypt.rs`/`sign.rs` persisted unwrapped key material when UsageLimits were configured; fixed by cloning before unwrapping ([#959](https://github.com/Cosmian/kms/pull/959))
- **Attribute-mutation authorization bypass**: attribute ops (`SetAttribute`, `ModifyAttribute`, `AddAttribute`, `DeleteAttribute`) used relaxed `GetAttributes` permission; now require the correct per-operation permission ([#959](https://github.com/Cosmian/kms/pull/959))
- **HSM key permissions hardening**: admin-only Destroy; block `Destroy`/`Revoke` grants; `Locate` and `/access/owned` visibility filtering for non-admin users ([#942](https://github.com/Cosmian/kms/pull/942))
- **COSMIAN-2026-017 / COSMIAN-2026-018**: `ReKey` and `Activate` now check ownership / `KmipOperation::Activate` permission — previously any user with any grant could activate or rotate another user's key
- **ReKey / ReKeyKeyPair privileged-user enforcement**: both operations now respect `privileged_users` Create-permission gating, consistent with `Create`, `Import`, and `Register`
- **GPL dependency removal**: replace `actix-governor` (GPL-3.0-or-later) with a direct `governor` (MIT/Apache-2.0) middleware; remove `GPL-3.0-or-later` from `deny.toml` allow list ([#967](https://github.com/Cosmian/kms/pull/967))

### 🐛 Bug Fixes

#### VAST Data / KMIP 1.x Interoperability

- Fix `ReKey`, `DeriveKey`, `ReCertify`, `Check` returning `Invalid_Message` for KMIP 1.4 clients ([#845](https://github.com/Cosmian/kms/issues/845))
- Fix RFC 3394 vs RFC 5649 wrapping mismatch — default to `NISTKeyWrap` (RFC 3394) for `Get` with `KeyWrappingSpecification` ([#845](https://github.com/Cosmian/kms/issues/845))
- Fix `DerivationParameters` deserialization — `Salt`, `DerivationData`, `IterationCount` were silently ignored due to missing `#[serde(rename_all = "PascalCase")]` ([#845](https://github.com/Cosmian/kms/issues/845))
- Fix `ReKey` creating replacement key material in-place — now creates a new UID and links old/new via `ReplacementObjectLink`/`ReplacedObjectLink`; existing key State is **not** changed per KMIP 2.1 §6.1.46 ([#845](https://github.com/Cosmian/kms/issues/845))

#### Google CSE

- Fix `InvalidAudience` rejecting all CSE authorization tokens with jsonwebtoken 10.x ([#947](https://github.com/Cosmian/kms/issues/947))
- Fix KACLS migration `rewrap`/`privilegedunwrap` flow — set expected audience `"kacls-migration"` for whitelist configs ([#947](https://github.com/Cosmian/kms/issues/947))
- Add JWKS refresh-retry on validation failure to prevent permanent auth failures after periodic refresh errors ([#947](https://github.com/Cosmian/kms/issues/947))
- Register `POST /google_cse/wrapprivatekey` endpoint in the Google CSE scope — was defined but not reachable

#### Multi-HSM

- Fix longest-prefix matching in `get_object_store` — model-based UIDs (`hsm::softhsm2::0::key`) were routed to legacy `hsm` backend ([#942](https://github.com/Cosmian/kms/pull/942))
- Fix `HsmStore::find()`/`atomic()` hardcoded `"hsm::"` prefix breaking multi-HSM setups ([#942](https://github.com/Cosmian/kms/pull/942))
- Fix `Get`↔`Export` equivalence — holding either now grants both on HSM keys ([#942](https://github.com/Cosmian/kms/pull/942))
- Fix SQL `INNER JOIN objects` excluding HSM keys from `/access/obtained` results — changed to `LEFT JOIN` ([#942](https://github.com/Cosmian/kms/pull/942))

#### Certificates / WASM

- Fix `id-ce-noRevAvail` OID (`2.5.29.56`) was incorrectly set to `1.3.6.1.5.5.7.1.56`; `noRevAvail` now excluded from CA certs per RFC 9608 §3
- Fix WASM empty-string `Option<String>` passed as `Some("")` causing `422 Object_Not_Found` for cleared form fields
- Fix `certificatePolicies` extension failing with "no config database" when a CPS qualifier (`CPS:url` or `CPS.N:url`) is in `--certificate-extensions` CNF; replaced OpenSSL conf-based `X509Extension::new_nid` path with a native Rust DER builder (also handles numbered `CPS.1:`, `CPS.2:` syntax)

#### Misc

- Fix ECDSA verify returning HTTP 500 on corrupted signature instead of `{"valid": false}`
- Fix Web UI `AccessGrant`/`AccessRevoke` hardcoded 8-operation list — replaced with WASM-exported dynamic list of all 21 operations ([#959](https://github.com/Cosmian/kms/pull/959))
- Fix `KmipOperation::to_string()` serialisation — grant/revoke for attribute operations returned HTTP 400 `unknown variant 'set_attribute'` ([#959](https://github.com/Cosmian/kms/pull/959))
- Fix `Activate` on `Destroyed` or `Compromised` objects returning `Object_Not_Found` — now returns the correct `Wrong_Key_Lifecycle_State` KMIP error
- Fix `operation_types` enum values in `openapi.yaml` (were PascalCase; server expects lowercase due to `#[serde(rename_all = "lowercase")]`); fix `/access/create` and `/access/privileged` response schemas; document `POST /v1/crypto/keys` 400 response
- Fix test temp-directory collisions: embed `std::process::id()` in path names to prevent SQLite `database is locked` failures under parallel `cargo test --workspace`

#### UI Encryption

- Fix HTML error page displayed in UI when encrypt payload exceeds server limit — KMIP endpoint now returns plain text errors instead of HTML ([#966](https://github.com/Cosmian/kms/issues/966))
- Fix WASM panic "capacity overflow" encrypting large files — TTLV serializer accumulates `Vec<u8>` byte-like tags directly into a `ByteString` instead of allocating one TTLV element per byte; prevents OOM on 32-bit WASM for payloads >~10 MB ([#967](https://github.com/Cosmian/kms/pull/967))
- Fix client-side upload limit: corrected from 45 MB to 30 MB to account for TTLV hex encoding (2× expansion); a 35 MB file produces a ~70 MB JSON body, exceeding the server's 64 MB payload limit ([#967](https://github.com/Cosmian/kms/pull/967))

### ♻️ Refactor

- KMIP `fmt::Display`/`fmt::Debug`: replaced with `impl_display!`/`debug_from_display!` macros (~330 lines saved)
- Server attribute operations: new `attribute_ops_dispatch.rs` with shared macros (`match_add_attribute!`, etc.) (~1 126 lines saved)
- Server lifecycle helpers: extracted `setup_object_lifecycle()`, `fill_missing_cp_fields()` into `state_utils.rs` (~165 lines saved)
- Web UI: shared `useActionState` hook and `ActionResponse` component across 66 action components (~3 177 lines saved)
- Generic `CryptoOpSpec` trait unifying all 6 crypto operations (Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify) into `perform_crypto_operation<Op>()` ([#959](https://github.com/Cosmian/kms/pull/959))
- **Net**: 72 files changed, −3 177 net lines ([#959](https://github.com/Cosmian/kms/pull/959))

### 🧪 Testing

- KMIP regression vector infrastructure: 8 integration suites converted to binary TTLV wire format (KMIP 1.0–1.4); FortiGate, MySQL, Percona, Synology DSM, Veeam, VMware, MongoDB, PyKMIP ([#953](https://github.com/Cosmian/kms/pull/953))
- 24 Known-Answer Test (KAT) vectors (NIST FIPS 180-4/202, SP 800-38A/D, RFC 4231/8439/8452/5869/8018/7539); 39 new dynamic vectors (PQC, Ed448, secp256k1, ChaCha20, AES-XTS, key-wrap)
- 31 Certify integration tests and 26 PQC chain validation tests; 15 PQC self-signed CLI test cases (non-FIPS)
- VAST Data regression vector: 10-step AES key lifecycle (Create→Activate→ReKey→Check→Get→Destroy) ([#845](https://github.com/Cosmian/kms/issues/845))
- KEK wrapping regression tests: `test_decrypt_preserves_kek_wrapping_with_usage_limits`, `test_sign_preserves_kek_wrapping_with_usage_limits` ([#959](https://github.com/Cosmian/kms/pull/959))
- 32 HSM key authorization non-regression scenarios in `crate/server/src/tests/hsm/permissions.rs` ([#942](https://github.com/Cosmian/kms/pull/942))
- JOSE integration tests (`encrypt_decrypt`, `sign_verify`, `mac`, `error_cases`, `rfc_vectors`) + Python `jwcrypto` interop ([#929](https://github.com/Cosmian/kms/pull/929))
- Access control privilege escalation vectors: self-grant, non-owner grant, destroy without permission ([#959](https://github.com/Cosmian/kms/pull/959))
- Total: 134→148+ vectors, 1 127→1 154+ tests
- TTLV serializer regression test: 1 MB `Vec<u8>` round-trip via `ByteString` (verifies no capacity overflow) ([#967](https://github.com/Cosmian/kms/pull/967))
- 24 new `ReKeyKeyPair` test vectors (RSA, EC, PQC, edge cases); 3 KMIP 1.4 protocol vectors; access-control vectors for ReKey/Activate privilege escalation ([#845](https://github.com/Cosmian/kms/issues/845))
- `certificatePolicies` positive and negative unit tests (`test_certificate_policies_with_cps_qualifier`, `test_old_new_nid_fails_for_cps_syntax`); bash regression script `.github/scripts/test/test_certificate_policies.sh`
- Playwright E2E suite `swagger.spec.ts`: OpenAPI spec structure, HTTP contracts, CSP headers, locally-served assets, live server cross-validation

### 📚 Documentation

- New `documentation/docs/integrations/jose_api.md` — JOSE REST API reference with examples ([#868](https://github.com/Cosmian/kms/issues/868))
- New `documentation/docs/hsm_support/multi_hsm.md` — multi-HSM routing, TOML config, `/hsm/status` endpoint ([#942](https://github.com/Cosmian/kms/pull/942))
- PKI page consolidated: `pqc_x509_certificates.md` → `pki.md`; covers RFC 5280/8017/5480/8032/9881/9909/9935/9608 and classical + PQC algorithms ([#943](https://github.com/Cosmian/kms/pull/943))
- New `documentation/docs/integrations/storage/vast_data.md` — VAST Data setup, KEK/DEK workflow, troubleshooting ([#845](https://github.com/Cosmian/kms/issues/845))
- JOSE security audit report: `documentation/docs/certifications_and_compliance/audit/jose_security_audit_2026_05.md` ([#929](https://github.com/Cosmian/kms/pull/929))
- `authorization.md` updated with all 22 delegable operations including attribute ops; `TESTS.md` added with test architecture, mermaid diagrams, and vector format spec ([#959](https://github.com/Cosmian/kms/pull/959))
- New `documentation/docs/kmip_support/openapi.md` — OpenAPI/Swagger UI usage, endpoints, tooling integration, security headers, and spec versioning; registered in `documentation/mkdocs.yml` under KMIP Support; `README.md` updated with OpenAPI 3.1 and Swagger UI mentions
- VAST Data integration doc (`vast_data.md`) updated: workflow description and sequence diagram corrected — old key remains Active after `ReKey`; `Revoke` + `Destroy` must be called explicitly on both old and new keys

### ⚙️ CI

- Oracle TDE: refactored CI into standalone `upgrade-kms.sh` + `smoke-test-tde.sh` scripts; 6/6 TDE proofs validated on Oracle 23ai Free with Cosmian PKCS#11 provider ([#918](https://github.com/Cosmian/kms/pull/918))
- New `jose` CI test type (non-FIPS): curl-based REST crypto tests + Python `jwcrypto` interoperability ([#929](https://github.com/Cosmian/kms/pull/929))
- Add `cargo deny list -l crate > sbom/licenses.txt` pre-commit hook; automate SBOM license generation in `release.yml` `prepare` job ([#967](https://github.com/Cosmian/kms/pull/967))

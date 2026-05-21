## [Unreleased]

### 🚀 Features

#### PQC X.509 Certificates

- **Server — PQC X.509 certificate issuance**: the `Certify` operation now supports ML-DSA-44/65/87 and all SLH-DSA variants (SHA2 / SHAKE × 128s/f / 192s/f / 256s/f) as both subject key algorithms and issuer signing keys (non-FIPS only). The digest selection in `build_and_sign_certificate` previously used the subject's key type and fell through to `SHA-256` for PQC keys; it now correctly uses the issuer's signing key type and maps any non-RSA/EC key (EdDSA, ML-DSA, SLH-DSA) to `MessageDigest::null()` (internal digest).
- **Server — RFC 9881 / RFC 9935 key usage extensions**: the `Certify` operation automatically adds the RFC-mandated critical `keyUsage` extension to all PQC certificates: `digitalSignature` for ML-DSA and SLH-DSA (RFC 9881 §5); `keyEncipherment` only for ML-KEM (RFC 9935 §5).
- **Server — ML-KEM X.509 certificates (RFC 9935)**: CA-issued X.509 certificates for ML-KEM-512/768/1024 subject keys are now supported. ML-KEM self-signed requests are explicitly rejected with a clear error message.
- **CLI — PQC algorithms in `certificates certify --algorithm`**: the `Algorithm` enum in `certificate_utils` now includes all ML-DSA (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) and SLH-DSA variants as valid `--algorithm` values for `--generate-key-pair` mode (non-FIPS only).
- **Web UI / WASM — PQC algorithms in Certificate Certify form**: `get_certificate_algorithms()` now includes all ML-DSA and SLH-DSA algorithm options (non-FIPS only), so the *Generate New Keypair* dropdown in the Certificate Certify form exposes all PQC signing algorithms.
- **CLI tests — full PQC algorithm coverage for certificate generation**: added `fetch_pqc_certificate` helper (using `x509_parser` instead of the OpenSSL bindings so PQC OIDs are handled correctly) and `certify_pqc_self_signed` shared helper; added 15 new `#[tokio::test]` cases covering self-signed certificates for every PQC signing algorithm (ML-DSA-65/87, SLH-DSA-SHA2-128s/f, SLH-DSA-SHA2-192s/f, SLH-DSA-SHA2-256s/f, SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-192s/f, SLH-DSA-SHAKE-256s/f) plus a cross-algorithm test (SLH-DSA CA signing an ML-DSA leaf).

### 🐛 Bug Fixes

- **Server — `id-ce-noRevAvail` OID and CA exclusion fix**: the `noRevAvail` extension block in `build_and_sign_certificate` contained AI-generated errors identified by code review: (1) wrong OID `1.3.6.1.5.5.7.1.56` (`id-pe` arc) corrected to `2.5.29.56` (`id-ce 56`); (2) wrong name `id-pe-noRevAvail` corrected to `id-ce-noRevAvail`; (3) wrong RFC section `RFC 9608 §4` corrected to `RFC 9608 §2`; (4) non-existent sub-section `§4.3.1` removed. Additionally, a logic bug was fixed: RFC 9608 §3 mandates that `noRevAvail` MUST NOT appear in CA public key certificates; the extension is now only added to self-signed end-entity certificates.
- **E2E UI — `self-signed Ed25519` test fails in FIPS mode**: the `certificates-certify.spec.ts` test for Ed25519 was missing the `test.skip(FIPS_MODE, ...)` guard. Ed25519 is not available in FIPS mode; the test now correctly skips in FIPS builds (`PLAYWRIGHT_FIPS_MODE=true`). ([#943](https://github.com/Cosmian/kms/pull/943))

### ♻️ Refactor

- **Server — Certify operation: one file per RFC**: split the PQC extension logic from `certify/mod.rs` into dedicated submodules: `rfc9881.rs` (ML-DSA keyUsage), `rfc9909.rs` (SLH-DSA keyUsage), `rfc9935.rs` (ML-KEM keyUsage), and `rfc9608.rs` (noRevAvail). Shared helpers (`pqc_signing_key_usage`, `is_signing_capable`) remain in `mod.rs`. ([#943](https://github.com/Cosmian/kms/pull/943))

### 🧪 Testing

- **KMIP policy alignment with ANSSI crypto guide 3.0**: test verifying that the KMIP policy configuration is aligned with the latest ANSSI cryptographic recommendations (guide version 3.0).
- **RFC 9881 compliance test**: `test_rfc9881_ml_dsa_key_usage_critical_digital_signature` verifies that ML-DSA-44 self-signed certificates carry a critical `keyUsage` extension with `digitalSignature` (x509_parser flag bit 0).
- **RFC 9881 non-regression test**: `test_rfc9881_ml_dsa_87_key_usage` verifies that ML-DSA-87 certificates also carry the correct critical `keyUsage`.
- **RFC 9935 compliance test**: `test_rfc9935_ml_kem_key_usage_critical_key_encipherment_only` verifies that CA-issued ML-KEM-512 certificates carry a critical `keyUsage` extension with `keyEncipherment` only (flags = 4, no other bits).
- **RFC 9935 OID test**: `test_rfc9935_ml_kem_spki_oid` verifies that the `SubjectPublicKeyInfo` OID of an ML-KEM-512 certificate is `id-alg-ml-kem-512` (`2.16.840.1.101.3.4.4.1`).
- **X.509 structural compliance test**: `test_pqc_x509_structural_compliance` verifies X.509 v3 structure, OID consistency, DN equality (self-signed), and validity period for an ML-DSA-44 certificate.
- **Cryptographic signature verification test**: `test_pqc_ca_signature_verification` verifies that an ML-DSA-65 leaf certificate signed by an ML-DSA-44 CA passes `X509::verify()` against the CA's public key.
- **Server — PQC X.509 chain validation tests (26 tests)**: added `crate/server/src/tests/test_validate.rs::pqc_validate_tests` module with comprehensive coverage of the KMIP `Validate` operation for PQC certificate chains (non-FIPS only):
    - **1-level (self-signed root)**: ML-DSA-44/65/87, SLH-DSA-SHA2-128s each as standalone self-signed root certificates.
    - **2-level chains (root → leaf)**: ML-DSA-44→ML-DSA-44, ML-DSA-44→ML-DSA-87, ML-DSA-44→ML-KEM-512 (RFC 9935), ML-DSA-65→ML-KEM-768 (RFC 9935), ML-DSA-87→ML-KEM-1024 (RFC 9935), SLH-DSA→ML-DSA-44, SLH-DSA→ML-KEM-512.
    - **3-level chains (root → intermediate → leaf)**: all-ML-DSA (44→65→87), ML-DSA-65 chain with ML-KEM-768 leaf (RFC 9935), SLH-DSA root → ML-DSA intermediate → ML-DSA leaf.
    - **Chain ordering**: out-of-order input (leaf, intermediate, root) is correctly sorted by `sort_certificates` and validates successfully.
    - **Failure cases**: ML-KEM self-signed rejected at `Certify`, future validity time (year 4804) fails, missing intermediate fails, missing root fails, empty chain fails, leaf with wrong issuer fails.
    - **Edge cases**: all three ML-DSA variants as self-signed roots, all three ML-KEM variants as CA-issued leaves, duplicate cert IDs deduplicated.
- **Server — `sort_certificates` RFC 5280 §4.2.1.1 fix**: extended root detection to also match self-signed certificates by comparing `issuer_name == subject_name`, in addition to the `SKI == AKI` method.  RFC 5280 explicitly permits AKI to be omitted for self-signed (root) CA certificates; PQC root CAs generated in-process cannot include `authorityKeyIdentifier=keyid:always,issuer` because no issuer cert is available in the OpenSSL `X509V3Context`.
- **Server — `pqc_rfc_key_usage` CA-awareness fix**: `build_and_sign_certificate` now passes `is_ca` to `pqc_rfc_key_usage`.  For CA certificates (`basicConstraints=CA:TRUE` in the vendor extension attribute), `keyCertSign` and `cRLSign` are included alongside `digitalSignature` in the critical `keyUsage` extension.  RFC 5280 §4.2.1.3 requires `keyCertSign` when `keyUsage` is present on a CA certificate; OpenSSL's `X509_verify_cert` enforces this check.
- **E2E — `certificates-certify.spec.ts`**: new Playwright spec with 27 tests covering all four certification methods and every supported algorithm:
    - Method 4 (generate new keypair): RSA-2048, RSA-4096, P-256, P-384, P-521, Ed25519 (skipped in FIPS), ML-DSA-44/65/87, SLH-DSA-SHA2-128s/f/192s/256s, SLH-DSA-SHAKE-128s/256s; ML-KEM-512 self-sign rejected by server.
    - Method 2 (existing public key): EC P-256 self-signed; ML-DSA-44 self-signed.
    - Method 3 (re-certify): renews an existing certificate.
    - CA-issued: ML-KEM-512/768/1024 and RSA-4096 leaves issued by an ML-DSA-44 CA.
    - Optional certificate ID: custom UUID is preserved in the response.
    - PQC tests are automatically skipped in FIPS mode (`PLAYWRIGHT_FIPS_MODE=true`).
    - Added `createCertificate` helper to `helpers.ts` for reuse across test files.
    - Added `data-testid="cert-algorithm-select"` to the algorithm `<Select>` in `CertificateCertify.tsx`.
- **Server — Certify operation integration tests (31 tests)**: added `crate/test_kms_server/src/certify_tests.rs` with comprehensive coverage of the Certify operation across all Subject×Issuer paths:
    - **KeypairAndSubjectName**: self-signed (RSA, EC, Ed25519, ML-DSA, SLH-DSA) + CA-signed (RSA, EC, Ed25519, ML-DSA, SLH-DSA, ML-KEM).
    - **PublicKeyAndSubjectName**: self-signed (RSA, EC, Ed25519) + CA-signed (RSA, EC, Ed25519, ML-DSA, SLH-DSA, ML-KEM).
    - **Certificate renewal**: self-signed (RSA, EC, Ed25519) + CA-signed (RSA, EC, Ed25519).
    - **CSR-based certification**: CA-signed (RSA, EC, Ed25519) using pre-generated test CSR PEM files.
    - **Negative tests**: ML-KEM self-sign rejected, CSR without issuer rejected.
    - PQC tests are gated with `#[cfg(feature = "non-fips")]` (15 FIPS-only, 31 non-FIPS).

### 📚 Documentation

- **PKI page consolidation**: renamed `pqc_x509_certificates.md` to `pki.md`, broadening scope to cover all supported X.509 standards (RFC 5280, 8017, 5480, 8032, 9881, 9909, 9935, 9608), classical algorithms (RSA, EC, EdDSA), PKCS#12 export, and an explicit "Not supported" section (Merkle Tree Certificates, Composite Certificates, OCSP responder, CRL generation). ([#943](https://github.com/Cosmian/kms/pull/943))
- **Post-Quantum X.509 certificates — RFC references updated**: the `pqc_x509_certificates.md` page now references finalized RFCs: SLH-DSA row changed from `draft-ietf-lamps-x509-slh-dsa` to **RFC 9909** (published March 2025); **RFC 9608** (`id-ce-noRevAvail`) added to the standards table; hyperlinks added for RFC 9881, 9935, 9909, 9608, and RFC 5280.
- **New section — Revocation handling**: documents CRL distribution points (existing), AIA / `authorityInfoAccess` (now unblocked, see fix below), `id-ce-noRevAvail` for offline/self-signed PKI (auto-added by this release), and OCSP as future work.
- **New section — Composite PQC (future)**: explains the classical→PQC migration rationale (dual signatures for backward compatibility) and references `draft-ietf-lamps-pq-composite-sigs-19`; no implementation in this release.

### 🚀 Features (continued)

- **Server — `id-ce-noRevAvail` auto-generation (RFC 9608)**: `build_and_sign_certificate` now automatically adds the `id-ce-noRevAvail` extension (OID 2.5.29.56, `{ id-ce 56 }`, RFC 9608 §2) to every **self-signed** certificate that carries no `crlDistributionPoints` in its extension config. Applies to **all algorithms** (RSA, EC, ML-DSA, SLH-DSA, …), not only PQC. The extension signals to relying parties that no revocation information is available so they must not reject the certificate for lack of a CRL or OCSP response.
- **Server — CRL skip for `noRevAvail` certificates**: `verify_crls` now calls the new `cert_has_no_rev_avail(cert)` helper; if the extension is present, the CRL fetch is skipped for that certificate.
- **Server — `authorityInfoAccess` (AIA) extension support fixed**: the `x509_extensions.rs` parser now handles the `authorityInfoAccess` key (OID 1.3.6.1.5.5.7.1.1) via `Nid::INFO_ACCESS`, unblocking the previously commented-out `// Nid????` placeholder. Value format: `OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt`.
- **Server — `noRevAvail` extension config support**: the `x509_extensions.rs` parser now also handles a `noRevAvail` key in the `[v3_ca]` section, allowing explicit opt-in via `--certificate-extensions` (e.g., for CA-issued certs that also have no CRL DP).

### 🧪 Testing (continued)

- **Server — `test_validate_pqc_self_signed_has_no_rev_avail`**: verifies that a self-signed ML-DSA-44 cert automatically carries OID `2.5.29.56` (id-ce-noRevAvail, RFC 9608 §2) in its extensions (parsed with x509-parser) and that `Validate` returns `Valid` (CRL check skipped due to noRevAvail).
- **CLI — `test_certify_pqc_self_signed_no_rev_avail`**: verifies that a self-signed ML-DSA-44 cert exported from the KMS carries OID `2.5.29.56` (id-ce-noRevAvail).
- **CLI — `test_certify_no_rev_avail_openssl_compat`**: new OpenSSL 3 compatibility test — passes the DER cert to `openssl x509 -text` and asserts that the output contains "No Revocation" or the dotted OID `2.5.29.56`, and that the old wrong OID `1.3.6.1.5.5.7.1.56` does not appear. Skipped automatically when OpenSSL 3 is not on `PATH`.
- **CLI — `test_certify_with_aia_extension`**: verifies that specifying `authorityInfoAccess=OCSP;URI:…` in `--certificate-extensions` produces a cert with AIA OID 1.3.6.1.5.5.7.1.1.
- **E2E — `cert-lifecycle.spec.ts`**: added "RFC 9608 – ML-DSA-44 self-signed cert with noRevAvail validates" test: creates a self-signed ML-DSA-44 cert via the UI then validates it (confirms CRL skip works end-to-end).

### 🐛 Bug Fixes (continued)

- **All files — `id-ce-noRevAvail` OID audit and correction**: a comprehensive audit of all RFC 9608 references in the codebase found that four additional files (`x509_extensions.rs`, `validate.rs`, `test_validate.rs`, `certify.rs` CLI test) still carried the wrong OID `1.3.6.1.5.5.7.1.56` (id-pe arc) instead of `2.5.29.56` (id-ce 56), the wrong extension name `id-pe-noRevAvail`, and wrong DER bytes `[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x38]` instead of `[0x55, 0x1d, 0x38]`. The critical runtime bug was in `cert_has_no_rev_avail()` in `validate.rs`: since `certify/mod.rs` now emits `2.5.29.56`, the old function would never detect the extension and would never skip CRL checks. All five locations are now corrected. The documentation `pqc_x509_certificates.md` was also updated (three occurrences). Verified against [RFC 9608 §2](https://www.rfc-editor.org/rfc/rfc9608#section-2) live.

- **New page — Post-Quantum X.509 Certificates**: added `documentation/docs/use_cases/pqc_x509_certificates.md` covering RFC 9881 (ML-DSA), RFC 9935 (ML-KEM), and draft-ietf-lamps-x509-slh-dsa (SLH-DSA) with OID tables, CLI examples, key usage requirements, cross-algorithm PKI guidance, and OpenSSL verification instructions.
- **Updated `_certify.md`**: added a PQC section describing ML-DSA, SLH-DSA, and ML-KEM certificate issuance with links to the new PQC X.509 documentation page.

Closes #943

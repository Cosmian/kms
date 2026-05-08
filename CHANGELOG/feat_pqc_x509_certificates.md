## [Unreleased]

### 🚀 Features

#### PQC X.509 Certificates

- **Server — PQC X.509 certificate issuance**: the `Certify` operation now supports ML-DSA-44/65/87 and all SLH-DSA variants (SHA2 / SHAKE × 128s/f / 192s/f / 256s/f) as both subject key algorithms and issuer signing keys (non-FIPS only). The digest selection in `build_and_sign_certificate` previously used the subject's key type and fell through to `SHA-256` for PQC keys; it now correctly uses the issuer's signing key type and maps any non-RSA/EC key (EdDSA, ML-DSA, SLH-DSA) to `MessageDigest::null()` (internal digest).
- **Server — RFC 9881 / RFC 9935 key usage extensions**: the `Certify` operation automatically adds the RFC-mandated critical `keyUsage` extension to all PQC certificates: `digitalSignature` for ML-DSA and SLH-DSA (RFC 9881 §4); `keyEncipherment` only for ML-KEM (RFC 9935 §5).
- **Server — ML-KEM X.509 certificates (RFC 9935)**: CA-issued X.509 certificates for ML-KEM-512/768/1024 subject keys are now supported. ML-KEM self-signed requests are explicitly rejected with a clear error message.
- **CLI — PQC algorithms in `certificates certify --algorithm`**: the `Algorithm` enum in `certificate_utils` now includes all ML-DSA (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) and SLH-DSA variants as valid `--algorithm` values for `--generate-key-pair` mode (non-FIPS only).
- **Web UI / WASM — PQC algorithms in Certificate Certify form**: `get_certificate_algorithms()` now includes all ML-DSA and SLH-DSA algorithm options (non-FIPS only), so the *Generate New Keypair* dropdown in the Certificate Certify form exposes all PQC signing algorithms.
- **CLI tests — full PQC algorithm coverage for certificate generation**: added `fetch_pqc_certificate` helper (using `x509_parser` instead of the OpenSSL bindings so PQC OIDs are handled correctly) and `certify_pqc_self_signed` shared helper; added 15 new `#[tokio::test]` cases covering self-signed certificates for every PQC signing algorithm (ML-DSA-65/87, SLH-DSA-SHA2-128s/f, SLH-DSA-SHA2-192s/f, SLH-DSA-SHA2-256s/f, SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-192s/f, SLH-DSA-SHAKE-256s/f) plus a cross-algorithm test (SLH-DSA CA signing an ML-DSA leaf).

### 🐛 Bug Fixes

- **E2E UI — `self-signed Ed25519` test fails in FIPS mode**: the `certificates-certify.spec.ts` test for Ed25519 was missing the `test.skip(FIPS_MODE, ...)` guard. Ed25519 is not available in FIPS mode; the test now correctly skips in FIPS builds (`PLAYWRIGHT_FIPS_MODE=true`). ([#943](https://github.com/Cosmian/kms/pull/943))

### 🧪 Testing

- **KMIP policy alignment with ANSSI crypto guide 3.0**: test verifying that the KMIP policy configuration is aligned with the latest ANSSI cryptographic recommendations (guide version 3.0).
- **RFC 9881 compliance test**: `test_rfc9881_ml_dsa_key_usage_critical_digital_signature` verifies that ML-DSA-44 self-signed certificates carry a critical `keyUsage` extension with `digitalSignature` (x509_parser flag bit 0).
- **RFC 9881 non-regression test**: `test_rfc9881_ml_dsa_87_key_usage` verifies that ML-DSA-87 certificates also carry the correct critical `keyUsage`.
- **RFC 9935 compliance test**: `test_rfc9935_ml_kem_key_usage_critical_key_encipherment_only` verifies that CA-issued ML-KEM-512 certificates carry a critical `keyUsage` extension with `keyEncipherment` only (flags = 4, no other bits).
- **RFC 9935 OID test**: `test_rfc9935_ml_kem_spki_oid` verifies that the `SubjectPublicKeyInfo` OID of an ML-KEM-512 certificate is `id-alg-ml-kem-512` (`2.16.840.1.101.3.4.4.1`).
- **X.509 structural compliance test**: `test_pqc_x509_structural_compliance` verifies X.509 v3 structure, OID consistency, DN equality (self-signed), and validity period for an ML-DSA-44 certificate.
- **Cryptographic signature verification test**: `test_pqc_ca_signature_verification` verifies that an ML-DSA-65 leaf certificate signed by an ML-DSA-44 CA passes `X509::verify()` against the CA's public key.
- **E2E — `certificates-certify.spec.ts`**: new Playwright spec with 27 tests covering all four certification methods and every supported algorithm:
    - Method 4 (generate new keypair): RSA-2048, RSA-4096, P-256, P-384, P-521, Ed25519 (skipped in FIPS), ML-DSA-44/65/87, SLH-DSA-SHA2-128s/f/192s/256s, SLH-DSA-SHAKE-128s/256s; ML-KEM-512 self-sign rejected by server.
    - Method 2 (existing public key): EC P-256 self-signed; ML-DSA-44 self-signed.
    - Method 3 (re-certify): renews an existing certificate.
    - CA-issued: ML-KEM-512/768/1024 and RSA-4096 leaves issued by an ML-DSA-44 CA.
    - Optional certificate ID: custom UUID is preserved in the response.
    - PQC tests are automatically skipped in FIPS mode (`PLAYWRIGHT_FIPS_MODE=true`).
    - Added `createCertificate` helper to `helpers.ts` for reuse across test files.
    - Added `data-testid="cert-algorithm-select"` to the algorithm `<Select>` in `CertificateCertify.tsx`.

### 📚 Documentation

- **New page — Post-Quantum X.509 Certificates**: added `documentation/docs/use_cases/pqc_x509_certificates.md` covering RFC 9881 (ML-DSA), RFC 9935 (ML-KEM), and draft-ietf-lamps-x509-slh-dsa (SLH-DSA) with OID tables, CLI examples, key usage requirements, cross-algorithm PKI guidance, and OpenSSL verification instructions.
- **Updated `_certify.md`**: added a PQC section describing ML-DSA, SLH-DSA, and ML-KEM certificate issuance with links to the new PQC X.509 documentation page.

Closes #943

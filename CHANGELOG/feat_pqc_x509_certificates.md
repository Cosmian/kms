## [Unreleased]

### 🚀 Features

#### PQC X.509 Certificates

- **Server — PQC X.509 certificate issuance**: the `Certify` operation now supports ML-DSA-44/65/87 and all SLH-DSA variants (SHA2 / SHAKE × 128s/f / 192s/f / 256s/f) as both subject key algorithms and issuer signing keys (non-FIPS only). The digest selection in `build_and_sign_certificate` previously used the subject's key type and fell through to `SHA-256` for PQC keys; it now correctly uses the issuer's signing key type and maps any non-RSA/EC key (EdDSA, ML-DSA, SLH-DSA) to `MessageDigest::null()` (internal digest).
- **CLI — PQC algorithms in `certificates certify --algorithm`**: the `Algorithm` enum in `certificate_utils` now includes all ML-DSA (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) and SLH-DSA variants as valid `--algorithm` values for `--generate-key-pair` mode (non-FIPS only).
- **Web UI / WASM — PQC algorithms in Certificate Certify form**: `get_certificate_algorithms()` now includes all ML-DSA and SLH-DSA algorithm options (non-FIPS only), so the *Generate New Keypair* dropdown in the Certificate Certify form exposes all PQC signing algorithms.
- **CLI tests — full PQC algorithm coverage for certificate generation**: added `fetch_pqc_certificate` helper (using `x509_parser` instead of the OpenSSL bindings so PQC OIDs are handled correctly) and `certify_pqc_self_signed` shared helper; added 15 new `#[tokio::test]` cases covering self-signed certificates for every PQC signing algorithm (ML-DSA-65/87, SLH-DSA-SHA2-128s/f, SLH-DSA-SHA2-192s/f, SLH-DSA-SHA2-256s/f, SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-192s/f, SLH-DSA-SHAKE-256s/f) plus a cross-algorithm test (SLH-DSA CA signing an ML-DSA leaf).

### 🧪 Testing

- **KMIP policy alignment with ANSSI crypto guide 3.0**: test verifying that the KMIP policy configuration is aligned with the latest ANSSI cryptographic recommendations (guide version 3.0).
- **E2E — `certificates-certify.spec.ts`**: new Playwright spec with 27 tests covering all four certification methods and every supported algorithm:
    - Method 4 (generate new keypair): RSA-2048, RSA-4096, P-256, P-384, P-521, Ed25519, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/f/192s/256s, SLH-DSA-SHAKE-128s/256s; ML-KEM-512 self-sign rejected by server.
    - Method 2 (existing public key): EC P-256 self-signed; ML-DSA-44 self-signed.
    - Method 3 (re-certify): renews an existing certificate.
    - CA-issued: ML-KEM-512/768/1024 and RSA-4096 leaves issued by an ML-DSA-44 CA.
    - Optional certificate ID: custom UUID is preserved in the response.
    - PQC tests are automatically skipped in FIPS mode (`PLAYWRIGHT_FIPS_MODE=true`).
    - Added `createCertificate` helper to `helpers.ts` for reuse across test files.
    - Added `data-testid="cert-algorithm-select"` to the algorithm `<Select>` in `CertificateCertify.tsx`.

# Changelog — feat/crypto_JWE_api

## Features

- Added REST crypto API under `/v1/crypto` — JOSE-compatible encrypt, decrypt, sign, verify,
  and MAC without a KMIP client library ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515),
  [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)):
    - `POST /v1/crypto/encrypt` — AES-GCM (`dir` + `A128/192/256GCM`)
    - `POST /v1/crypto/decrypt` — AES-GCM with AAD binding
    - `POST /v1/crypto/sign` — RS256/384/512, PS256/384/512, ES256/384/512 (+ EdDSA, MLDSA44 non-FIPS)
    - `POST /v1/crypto/verify` — JWS signature verification
    - `POST /v1/crypto/mac` — HMAC compute and verify (HS256/384/512)
- Added documentation: [`documentation/docs/integrations/rest_crypto_api.md`](documentation/docs/integrations/rest_crypto_api.md)

## Bug Fixes

- Fixed ECDSA verify returning HTTP 500 on a corrupted signature instead of `{"valid": false}`
  ([`crate/server/src/core/operations/signature_verify.rs`](crate/server/src/core/operations/signature_verify.rs),
  [`crate/server/src/routes/crypto/verify.rs`](crate/server/src/routes/crypto/verify.rs)).

## Security

- **H1/H2**: Validate GCM IV length (12 bytes) and authentication tag length (16 bytes) on decrypt — rejects non-standard sizes that weaken AES-GCM guarantees ([#929](https://github.com/Cosmian/kms/pull/929))
- **M1**: Explicitly reject `alg: "none"` in verify endpoint per RFC 8725 §2.1 ([#929](https://github.com/Cosmian/kms/pull/929))
- **M2**: Sanitize error responses for 403/404/500 — no longer leaks internal key UIDs, DB paths, or user names ([#929](https://github.com/Cosmian/kms/pull/929))
- **L1**: Use deterministic JSON serialization for JWE/JWS protected headers — ensures cross-server AAD consistency ([#929](https://github.com/Cosmian/kms/pull/929))
- Added security audit report: [`documentation/docs/certifications_and_compliance/audit/jose_security_audit_2026_05.md`](documentation/docs/certifications_and_compliance/audit/jose_security_audit_2026_05.md) ([#929](https://github.com/Cosmian/kms/pull/929))

## Testing

- Added [`crate/server/src/tests/rest_crypto/`](crate/server/src/tests/rest_crypto/) — integration tests
  (`encrypt_decrypt`, `sign_verify`, `mac`, `error_cases`, `rfc_vectors`).
- Added [`.github/scripts/test/test_jose.sh`](.github/scripts/test/test_jose.sh) — unified JOSE E2E
  test suite: curl-based REST crypto tests + Python `jwcrypto` interoperability validation,
  wired into CI as `jose` test type (non-fips only) ([#929](https://github.com/Cosmian/kms/pull/929))
- Added regression tests for GCM IV/tag length validation, `alg: "none"` rejection ([#929](https://github.com/Cosmian/kms/pull/929))

Closes #868

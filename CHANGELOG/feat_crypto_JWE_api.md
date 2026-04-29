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

## Testing

- Added [`crate/server/src/tests/rest_crypto/`](crate/server/src/tests/rest_crypto/) — integration tests
  (`encrypt_decrypt`, `sign_verify`, `mac`, `error_cases`, `rfc_vectors`).
- Added [`.github/scripts/test/rest_crypto_test.sh`](.github/scripts/test/rest_crypto_test.sh) — shell-only
  E2E test suite (curl/sed/grep/base64/tr only; no python3 or jq), wired into
  [`.github/scripts/nix.sh`](.github/scripts/nix.sh) and
  [`.github/workflows/test_all.yml`](.github/workflows/test_all.yml).

Closes #868


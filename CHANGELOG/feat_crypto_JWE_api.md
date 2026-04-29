# Changelog — feat/crypto_JWE_api

## Features

### REST Native Crypto API (`/v1/crypto`)

- Added new HTTP REST endpoints under `/v1/crypto` implementing JOSE-compatible
  encrypt, decrypt, sign, verify, and MAC operations (RFC 7516 / RFC 7515 / RFC 7518).
  Key material never leaves the KMS; only ciphertext/signatures/MACs are transmitted.
  - `POST /v1/crypto/encrypt` — AES-GCM encryption (`dir` + `A128GCM`/`A192GCM`/`A256GCM`)
  - `POST /v1/crypto/decrypt` — AES-GCM decryption with AAD binding verification
  - `POST /v1/crypto/sign` — Detached JWS signing (RS256/384/512, PS256/384/512, ES256/384/512;
    EdDSA and MLDSA44 in non-FIPS builds)
  - `POST /v1/crypto/verify` — JWS signature verification
  - `POST /v1/crypto/mac` — HMAC compute and verify (HS256/HS384/HS512)
- Exposed `mac_verify` KMIP operation from the KMS core layer to support the REST API
  (`crate/server/src/core/operations/mac.rs`, `kms/kmip.rs`).
- Added integration tests for the REST crypto API under
  `crate/server/src/tests/rest_crypto/` (refactored into a module folder by category):
  - `encrypt_decrypt` — AES-GCM round-trips (128-bit, 256-bit), AAD binding
  - `sign_verify` — RSA-2048 and EC P-256 sign/verify round-trips; tamper rejection
  - `mac` — HMAC-SHA256 compute and verify
  - `error_cases` — unknown algorithm (422), nonexistent key (4xx), wrong key type
  - `rfc_vectors` — RFC 7515 §A.1 HMAC-SHA256 known-answer test (exact MAC pinned);
    RFC 7515 §A.2/A.3/A.4 known-key round-trips (RS256/ES256/ES512)
- Fixed a pre-existing routing bug: handler macros used full paths (`/v1/crypto/encrypt`)
  while also being registered under `web::scope("/v1/crypto")`, causing actix-web to
  double the prefix and make all crypto endpoints unreachable in tests.
- Added documentation page `documentation/docs/integrations/rest_crypto_api.md` with
  full endpoint reference, curl examples, and algorithm support matrix.

Closes #868

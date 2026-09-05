## Features

### API / Crypto
- Add ECDH-ES decrypt support to `/v1/crypto/decrypt` (RFC 7518 §4.6), covering `ECDH-ES`, `ECDH-ES+A128KW`, and `ECDH-ES+A256KW` key management with `A128GCM`/`A192GCM`/`A256GCM` content encryption. Supports EC static keys on `P-256`/`P-384`/`P-521` (FIPS-available) and, in non-FIPS builds, `OKP`/`X25519` static keys. The KMS acts as a decryption oracle only — there is no `/v1/crypto/encrypt` ECDH-ES sender path.
- Add `/v1/crypto/keys` key creation for `alg=ECDH-ES|ECDH-ES+A128KW|ECDH-ES+A256KW`, generating EC (`P-256`/`P-384`/`P-521`) or non-FIPS OKP (`X25519`) key pairs with `KeyAgreement` usage, distinct from the existing signature-only EC/OKP key creation path.
- Publish `X25519` static public keys via `/.well-known/jwks.json` (`kty=OKP`, `crv=X25519`, `use=enc`), previously silently skipped.
- Add a generic P-256/P-384/P-521 ECDH key-agreement primitive (`ecdh_key_agreement`) and a Concat KDF implementation (RFC 7518 Appendix C / NIST SP 800-56A) to `cosmian_kms_crypto`.

## Bug Fixes

### API
- Fix `/.well-known/jwks.json`: EC public keys authorized for `KeyAgreement` (but not `Verify`) were incorrectly published with a signature `use`/`alg` claim (`ES256`/`ES384`) instead of `use=enc` with no `alg`.

## Testing

### API / Crypto
- Add RFC 7518 Appendix C Concat KDF known-answer vectors and P-256/P-384/P-521 ECDH cross-derivation tests to `cosmian_kms_crypto`.
- Add a comprehensive ECDH-ES test suite (`crate/server/src/tests/jose/ecdh.rs`) covering round trips for all three `alg` variants across P-256/P-384/P-521 (and X25519 in non-FIPS builds), decrypt via a public-key `kid` (link-following), AAD binding, and negative cases (missing/unexpected `encrypted_key`, mismatched `epk.crv`, sign-only key rejection, X25519/EC key confusion, X25519 rejected in FIPS builds).

---

Closes #1033

# Rust cleanup: remove `dead_code` suppressions, centralise workspace dependencies

## Breaking Changes

### Kubernetes

- The CSI provider now enforces `objectVersion` in a `SecretProviderClass` object entry. When set, it must equal the lower-case hexadecimal SHA-256 digest of the object's current content; otherwise the mount fails with `FailedPrecondition`. The field was previously ignored, so any `objectVersion` that is not a content digest must be removed or emptied before upgrading. Documented in `documentation/docs/integrations/kubernetes/csi-provider.md` (the examples there now also use the `kmsUID` key the provider actually reads).

### Azure EKM

- Wrap and unwrap now check the KEK's lifecycle state up front, using the states accepted by the KMIP `Encrypt` (`Active`) and `Decrypt` (`Active`, `Deactivated`, `Compromised`) operations. A key that is not in an accepted state (for example a never-activated `PreActive` key) is refused with the Azure `KeyDisabled` error instead of a generic `InternalError`. A `Deactivated` key, which the preceding KMIP `Get` refuses, is likewise reported as `KeyDisabled` (HTTP 403) instead of `InternalError` (HTTP 500). Keys must be activated before use, as they already had to be.

### CLI

- `ckms` PKCS#11 benchmarks no longer expose the secp256k1 and Ed25519 sign/verify modes in FIPS builds; they remain available with `--features non-fips`.

## Features

### Security

- JWT `crit` (RFC 7515 §4.1.11) and nested-JWT `cty` headers are now rejected by every JWKS-keyed authenticator (Google CSE, OIDC, Auth Verifier, and the UI SSO login `id_token` check). `jsonwebtoken` parses `crit` but never enforces it. Google CSE tokens additionally must carry non-blank `alg` and `kid` headers.

### HSM

- Add `Session::encrypt_aes_cbc_multi_part` and `decrypt_aes_cbc_multi_part`: AES-CBC through a single PKCS#11 multi-part operation (`C_*Init`, `C_*Update` per part, `C_*Final`), producing the same ciphertext as the single-shot call.

### KMIP

- Add `CredentialValue::credential_type()`, the inverse of the Credential Type to Credential Value mapping.

## Bug Fixes

### Database

- `clear_database` (SQLite, PostgreSQL, MySQL) now also empties the `crls` table.

## Refactor

- Remove every `#[allow(dead_code)]` / `#[expect(dead_code)]` suppression by deleting unused code or putting it to use; drop unused OCSP FFI declarations and unused SQL `Migrate` getters.
- Declare the workspace crate versions and shared dependencies once in the root `Cargo.toml`.
- Keep `#[cfg(feature = "non-fips")]` off function bodies in the PKCS#11 benchmark code.

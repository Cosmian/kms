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

### CLI

- `ckms bench --algorithm aes-gcm` (and `mise run bench:load -a aes-gcm`) now includes the JOSE AES-GCM benchmarks. The load op was named `jose/encrypt/a256gcm` and the Criterion filter matched JWA names (`A256GCM`), so the `aes-gcm` filter skipped both. The load op is now `jose/encrypt/aes-gcm`, which also puts it in the same report chart as the TTLV protocols, and `--key-size 128|192|256` filters the JOSE Criterion rows.

## Refactor

- Remove every `#[allow(dead_code)]` / `#[expect(dead_code)]` suppression by deleting unused code or putting it to use; drop unused OCSP FFI declarations and unused SQL `Migrate` getters.
- Declare the workspace crate versions and shared dependencies once in the root `Cargo.toml`.
- Keep `#[cfg(feature = "non-fips")]` off function bodies in the PKCS#11 benchmark code.
- Cut per-request heap copies on the KMIP TTLV-JSON path: `TtlvDeserializer` borrows the TTLV tree (`TtlvDeserializer<'a>` with the constructor `TtlvDeserializer::from_ttlv(&TTLV)`; the free function `from_ttlv(TTLV)` keeps its by-value signature and borrows internally) instead of cloning each subtree, `ByteString` values are hex-encoded/decoded without an intermediate `String`, the `/kmip/2_1` handler parses the body from `Bytes`, symmetric `Encrypt` borrows the key via `KeyBlock::key_bytes_ref()`, and `HttpClient` rebuilds a request only on connection retry (`post_bytes` now takes `impl Into<Bytes>`). In `TTLV->RequestMessage` decoding of a 4 KiB `Encrypt`, allocated bytes drop from 31 KB to 6.6 KB, and allocations drop from 89 to 5.
- Cut per-request allocations on the KMIP binary-TTLV path (`POST /kmip`, `application/octet-stream`). The handler decodes the request bytes once and gives the audit hooks the response TTLV it already has, instead of decoding the response bytes again. `TTLV::to_bytes` computes each Structure length up front and writes into one buffer of the exact size, instead of copying every nesting level through a temporary buffer. Header time stamps that are whole UTC seconds serialize straight to a TTLV `DateTime` node, through a `$KmipDateTime` newtype marker modelled on `Interval`; they no longer go through a 9-integer tuple. The wire decoder reserves at most 4 child slots per Structure and reads padding into a stack buffer. Wire output is byte-identical. For a 4 KiB `Encrypt`, encoding the response TTLV to bytes drops from 22 allocations / 26 KB to 1 / 4.3 KB.
- Speed up KMIP `ByteString` decoding: the TTLV deserializer no longer opens a tracing span and evaluates `cosmian_logger::trace!` once per byte. That macro computes the caller name even when tracing is disabled. Decoding a 4 KiB `Encrypt` from TTLV drops from 166 µs to 7 µs, which accounts for most of the per-request gap between the KMIP (`/kmip`, `/kmip/2_1`) and JOSE (`/v1/crypto`) endpoints.

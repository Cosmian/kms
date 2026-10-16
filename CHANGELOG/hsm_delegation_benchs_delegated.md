## Bug Fixes

### HSM

- Make HSM key-date handling capability-driven: `HsmCapabilities::supports_key_dates` now governs both reading and writing `CKA_START_DATE`/`CKA_END_DATE`. It is false for Crypt2pay and AWS CloudHSM (`CKR_ATTRIBUTE_TYPE_INVALID`) and SoftHSM2 (dates written on private keys can no longer be read back: `CKR_GENERAL_ERROR`, which made the key's metadata unreadable). On those HSMs, setting a rotation schedule now fails with an explicit error, and reading dates no longer silently swallows `CKR_ATTRIBUTE_TYPE_INVALID` on other vendors

## Refactor

### HSM

- Add `HsmCapabilities::supports_rsa_oaep_key_wrap` (false for SoftHSM2 and SmartCard-HSM) and `enforces_ecdsa_digest_strength` (true for AWS CloudHSM); RSA-OAEP `C_WrapKey`/`C_UnwrapKey` is refused up front where unsupported
- Remove vendor names and dead code (`build_keyset_label`) from `base_hsm` session code, route all capability reads through a single accessor, add missing `// SAFETY:` comments on PKCS#11 FFI calls, and read the key type once in `get_object_id`

## Testing

- Shared HSM tests read vendor differences from `slot.capabilities()` instead of caller-passed booleans and `HsmTestConfig` flags (`supports_rsa_wrap` and `rsa_oaep_digest` removed); `get_key_metadata` now round-trips key dates
- Remove the kryoptic-only `base_hsm/tests/kryoptic_conformance.rs` suite and its `test:hsm-kryoptic-conformance` task; the same PKCS#11 v3.0 checks run in `crate/hsm/kryoptic` via `mise run test:hsm-kryoptic`

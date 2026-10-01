## Features

### Client / WASM
- Expose every Covercrypt master-key re-key action as WASM exports building the matching `ReKeyKeyPair` TTLV request, for the Web UI and other WASM consumers: `rekey_cc_access_policy_ttlv_request`, `prune_cc_access_policy_ttlv_request`, `add_cc_attribute_ttlv_request`, `rename_cc_attribute_ttlv_request`, `disable_cc_attribute_ttlv_request`, `remove_cc_attribute_ttlv_request` and `add_cc_dimension_ttlv_request` (anarchic or hierarchical dimension). Encryption hints are given as `Classic`, `PostQuantum` or `Hybridized`.
- Add `CoverCryptRekeyAction`, `CoverCryptEncryptionHint` and `build_covercrypt_rekey_keypair_request` to `cosmian_kms_client_utils`: a copy of the server-side `RekeyEditAction` that does not depend on `cosmian_cover_crypt`, so it can be used from WASM, and that serializes to the same vendor attribute.

## Testing

### Client / WASM
- Add one `wasm_bindings` test per new Covercrypt re-key export.
- Add tests in `cosmian_kms_crypto` checking, for every `RekeyEditAction` variant, that the client-side request is identical to the server-side one and is read back as the same action. The conversion is an exhaustive `match`, so a new variant will not compile until the copy is updated.

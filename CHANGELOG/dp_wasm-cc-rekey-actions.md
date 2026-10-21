## Features

### Client / WASM

- Expose every Covercrypt master-key re-key action as WASM exports building the matching `ReKeyKeyPair` TTLV
  request, for the Web UI and other WASM consumers: `rekey_cc_access_policy_ttlv_request`,
  `prune_cc_access_policy_ttlv_request`, `add_cc_attribute_ttlv_request`, `rename_cc_attribute_ttlv_request`,
  `disable_cc_attribute_ttlv_request`, `remove_cc_attribute_ttlv_request` and `add_cc_dimension_ttlv_request`
  (anarchic or hierarchical dimension, given as `[name, encryption_hint]` pairs). Qualified attributes are written
  `Dimension::name`; malformed attributes and access policies are rejected client-side; encryption hints are
  given as `Classic`, `PostQuantum` or `Hybridized`. Like Covercrypt itself, these exports are only built with
  `non-fips`.
- Add a `non-fips` `cover_crypt_rekey_utils` module to `cosmian_kms_client_utils` (`CoverCryptRekeyAction`,
  `build_covercrypt_rekey_keypair_request`, hint, qualified-attribute and access-policy parsers): a copy of the server-side
  `RekeyEditAction` built on `cosmian_cover_crypt`'s own `EncryptionHint` and `QualifiedAttribute`, so it
  serializes to the same vendor attribute. `cosmian_cover_crypt` is used with its default features, which no
  longer pull OpenSSL, so it builds for WASM.

## Build

- Declare `cosmian_cover_crypt` once, as a workspace dependency on the `develop` branch of `cover_crypt` (16.0.1,
  optional OpenSSL dependency), shared by `cosmian_kms_crypto` and `cosmian_kms_client_utils`, until a release
  ships it.

## Testing

### Client / WASM

- Add a `wasm_bindings` test checking that each new Covercrypt re-key export accepts valid input and rejects
  malformed attributes, access policies and encryption hints.
- Add tests in `cosmian_kms_crypto` checking, for every `RekeyEditAction` variant, that the client-side request is
  identical to the server-side one and is read back as the same action. The conversion is an exhaustive `match`,
  so a new variant will not compile until the copy is updated.

# Fix import of hybrid-KEM and ConfigurableKEM keys

## Bug Fixes

### Server

- Fix `Import` of `X25519MLKEM768`, `X448MLKEM1024`, and `ConfigurableKEM` public and private keys
  failing with `Unsupported key format type: Raw` (resp. `ConfigurableKEMPublicKey`, ...
  `for transforming a PublicKey to openssl`): these keys have no OpenSSL/PKCS#8 representation, so
  `process_public_key` / `process_private_key` (`core/operations/import.rs`) now store them
  unmodified, like Covercrypt keys. This lets a hybrid public key be exported from one KMS and
  imported into another for offline encapsulation.
- Fix `Get`/`Export` of a `ConfigurableKEM` key failing on the OpenSSL conversion
  (`core/operations/export_get.rs`).
- Add regression tests `pqc_import_tests` (non-fips).

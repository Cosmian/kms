## Refactor

- Add default `map_selection_error` to `CryptoOpSpec` trait, eliminating identical implementations from Sign, SignatureVerify, MAC, and MACVerify operations (~48 LOC)
- Extract shared `run_encrypt`/`run_decrypt` helpers for CLI actions, deduplicating EC and RSA encrypt/decrypt implementations (~160 LOC)
- Replace `collect::<Vec<_>>().first().cloned()` with `find_map()` in HSM store RSA keypair detection
- Remove ~2,650 LOC of duplicated `shared/` test code from `cosmian_kms_cli_actions` that was covered by equivalent tests in `ckms`
    - Deleted entirely: `import.rs`, `wrap_unwrap.rs`, `import_export_wrapping.rs`, `import_export_encodings.rs`, `destroy.rs`, `export.rs`, `revoke.rs`
    - Trimmed `locate.rs` (609→120 LOC): kept only unique `test_locate_key_pair_and_sym_key` and `test_locate_secret_data`
    - Trimmed `export_import.rs` (395→275 LOC): kept only unique `test_openssl_cli_compat` and `test_google_cse_export_import`
    - Ported 3 unique secret-data lifecycle tests (`test_destroy_secret_data`, `test_revoke_secret_data`, `test_export_secret_data`) to ckms binary tests

## Bug Fixes

- Replace `drain().collect()` with `split_at()` in `parse_decrypt_elements` to avoid O(n) shift and take `&[u8]` instead of consuming the Vec
- Add `Vec::with_capacity` for response_items and success_indices in KMIP message batch processing

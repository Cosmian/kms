## Build

### Dependencies
- Remove the `fs4`, `etcetera`, `itertools`, `num-bigint` and `actix-rt` workspace dependencies in favor of the standard library and crates already in the workspace, and delete the unused `lazy_static`, `num-format`, `rand_core` and `tiny-keccak` declarations; no dependency is added or upgraded
- Replace `num_bigint::BigUint` with `num_bigint_dig::BigUint` in the public `cosmian_kms_crypto::crypto::fpe` API (`Integer::encrypt_big`, `decrypt_big`, `max_value`); ciphertexts and the KMIP/CLI wire formats are unchanged

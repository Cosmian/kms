## Refactor

- Remove ~6,300 LOC of duplicate test code from `cosmian_kms_cli_actions` that was already covered by equivalent tests in `ckms`
    - Deleted: `symmetric/`, `cover_crypt/`, `access.rs`, `auth_tests.rs`, `derive_key/`, `hash.rs`
    - Deleted overlapping: `elliptic_curve/create_key_pair.rs`, `elliptic_curve/encrypt_decrypt.rs`, `rsa/create_key_pair.rs`, `rsa/encrypt_decrypt.rs`
    - Deleted overlapping: `certificates/encrypt.rs`, `certificates/export.rs`, `certificates/import.rs`, `certificates/validate.rs`
    - Deleted overlapping: `attributes/test_modify_attribute.rs`, `google_cmd/key_pairs.rs`
    - Kept unique tests: `elliptic_curve/sign_verify.rs` (8 tests), `rsa/sign_verify.rs` (7 tests), `google_cmd/using_hsm.rs`, `certificates/certify.rs` (47 tests), `secret_data/` (8 tests)
    - Moved `run_encrypt_decrypt_test` helper to `tests/shared/encrypt_decrypt.rs` for HSM test reuse
- Remove ~836 LOC of additional overlapping tests after verifying ckms coverage
    - Deleted: `hsm/` (548 LOC) — all scenarios covered in ckms; ported `test_unwrap_with_hsm_key` (issue #762)
    - Deleted: `mac.rs` (98 LOC) — ported `test_mac_sha1` and `test_mac_sha224` to ckms
    - Deleted: `pqc/` (190 LOC) — ckms already covers identical algorithm variants (ML-KEM, ML-DSA, SLH-DSA, hybrid KEM)
    - Removed dead `shared/encrypt_decrypt.rs` helper (88 LOC)

## Testing

- Port `test_unwrap_with_hsm_key` regression test (issue #762) to `ckms` binary tests
- Port `test_mac_sha1` and `test_mac_sha224` algorithm variant tests to `ckms` binary tests

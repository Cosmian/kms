## Features

- Implement KMIP ReKey operation for symmetric keys with name transfer per §4.4
- Support re-wrapping of dependent keys when a wrapping key is rekeyed
- Add `find_wrapped_by()` method to `ObjectsStore` trait (SQLite, PostgreSQL, MySQL implementations)
- Implement KMIP `ReCertify` operation (§4.7) — certificate rotation with new UID and replacement links
- Add proper `ReCertify` and `ReCertifyResponse` KMIP 2.1 types compliant with both KMIP 1.x and 2.x
- Introduce `RekeyOperation` trait to unify symmetric, keypair, and certificate rotation logic
- Add `offset` field to `ReCertify` struct per KMIP 2.1 §6.1.45 for date-based activation scheduling

## Refactor

- Reorganize ReKey modules into `rekey/` folder: `mod.rs`, `symmetric.rs`, `keypair.rs`, `common.rs`; move `ReCertify` handler to `operations/recertify.rs` (top-level, parallel to `certify.rs`)
- Extract `RekeyOperation` trait into `common.rs` with `execute_rekey()` orchestrator — shared 2-phase commit logic
- Extract 6 shared helpers into `common.rs`: `compute_replacement_dates`, `prepare_replacement_attributes`, `update_old_key_after_rekey`, `set_rotation_metadata_on_new_key`, `clear_rotation_flags_on_old_key`, `enforce_privileged_user`
- Add `KeyRetirement` struct + `finalize_rekey` function in `common.rs` — shared Phase 2 logic (retire old keys + rewrap dependants + atomic commit) used by both symmetric and keypair rekey
- Move `compute_rotation_uid` and `rewrap_dependants` from `symmetric.rs` to `common.rs`; keypair rekey now uses name-preserving UIDs
- Convert `ReKeyKeyPair` to 2-phase commit (matching symmetric) to support dependant re-wrapping on public keys
- Set rotation metadata (`rotate_generation`, `rotate_date`, `rotate_latest`, `rotate_interval`) on new keys during `ReKeyKeyPair`
- Clear rotation flags on old keys during `ReKeyKeyPair` to prevent scheduler re-triggering
- Add default implementations to `RekeyOperation` trait for `detect_wrapping`, `persist_new_key`, `finalize_dependants`, and `rewrap_new_objects` — eliminates duplicate code across symmetric.rs, keypair.rs, and recertify.rs
- Extract `extract_rewrap_spec`, `extract_wrapping_key_uid`, and `retrieve_eligible_keys` into `common.rs` as shared helpers — removes 40+ lines of duplicated logic
- Extract shared `validate_no_crypto_param_change` into `common.rs` — validates that ReKey/ReKeyKeyPair requests do not alter algorithm, curve, or key length; now applies to both symmetric and keypair rekey
- Refactor `prepare_attributes` in `keypair.rs` — extract `finalize_replacement_key` helper to eliminate SK/PK code duplication
- Move `setup_new_key` and `finalize_replacement_key` from keypair.rs to common.rs as shared helpers
- Extract `preserve_wrapping_key_link` into common.rs — copies WrappingKeyLink from old to new key
- Split `rewrap_dependants` (70→25 lines) by extracting `rewrap_single_dependant` helper
- Split `relink_keys_to_new_certificate` by extracting `relink_single_key` helper

## Bug Fixes

- Transfer `Name` attribute from old key to new key during ReKey per KMIP §4.4
- Return error instead of silently skipping when a user-supplied wrapping key ID equals the key being wrapped
- Bypass ownership check for server-configured KEK during wrapping operations
- Fix symmetric ReKey missing server-wide KEK wrapping and unwrapped-cache insert (now consistent with keypair rekey via shared default)
- Fix keypair rekey not preserving WrappingKeyLink on replacement keys
- Fix symmetric rekey hardcoding `State::Active` — now uses `setup_object_lifecycle` for date-based state computation
- Fix `setup_object_lifecycle` not storing `activation_date` for `PreActive` keys — offset-based activation scheduling now works correctly
- Add `ReCertify` request/response deserialization to KMIP 2.1 message handler
- Fix `ReCertify.generate_replacement` passing empty user to `get_subject`/`get_issuer` — use certificate owner instead
- Fix `ReCertify` not computing lifecycle state from offset — certificates with future activation_date are now `PreActive`

## Documentation

- Add Certificate Renewal (ReCertify) section to key_auto_rotation.md with RFC references (RFC 4210, 4211, 5280, 2986, 5272), KMIP 2.1 §6.1.45 attribute table, and CMP relationship explanation

## Testing

- Add 9 symmetric ReKey test vectors (basic, wrapped, wrapping-key re-wrap, name transfer, offset, links)
- Add 27 ReKeyKeyPair test vectors (RSA, EC, ML-KEM, ML-DSA, SLH-DSA, X25519, secp256k1)
- Add Covercrypt ReKeyKeyPair test vector (in-place attribute rekey with same UIDs)
- Add access privilege escalation test vector for ReKey
- Add 4 ReCertify test vectors (self-signed, chain, with-links, with-offset)
- Add 3 negative ReCertify test vectors (missing UID, non-existent, not a certificate)
- Add 2 offset state verification vectors (rekey + rekey-keypair: Offset=0 → Active, Offset=86400 → PreActive)

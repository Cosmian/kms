## Features

- Implement KMIP ReKey operation for symmetric keys with name transfer per §4.4 ([#968](https://github.com/Cosmian/kms/pull/968))
- Support re-wrapping of dependent keys when a wrapping key is rekeyed ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `find_wrapped_by()` method to `ObjectsStore` trait (SQLite, PostgreSQL, MySQL implementations) ([#968](https://github.com/Cosmian/kms/pull/968))
- Implement KMIP `ReCertify` operation (§4.8) — certificate rotation with new UID and replacement links ([#968](https://github.com/Cosmian/kms/pull/968))
- Add proper `ReCertify` and `ReCertifyResponse` KMIP 2.1 types compliant with both KMIP 1.x and 2.x ([#968](https://github.com/Cosmian/kms/pull/968))
- Introduce `RekeyOperation` trait to unify symmetric, keypair, and certificate rotation logic ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `offset` field to `ReCertify` struct per KMIP 2.1 §6.1.45 for date-based activation scheduling ([#968](https://github.com/Cosmian/kms/pull/968))

## Security

- Mark `x-rotate-generation` and `x-rotate-date` as server-managed read-only attributes: reject user modifications via AddAttribute, SetAttribute, ModifyAttribute, and DeleteAttribute ([#968](https://github.com/Cosmian/kms/pull/968))
- Reject `Re-Key` and `Re-Key Key Pair` on HSM-managed keys (`hsm::` UID prefix) with an explicit `Not Supported` error instead of silently failing deep in the pipeline ([#968](https://github.com/Cosmian/kms/pull/968))

## Bug Fixes

- Fix `ReKeyKeyPair` not propagating `CryptographicUsageMask` from old key pair to the new `CreateKeyPair` request — causes FIPS-mode rejection (`got None but expected among 0x00103A01`) when rotating EC or RSA key pairs in a keyset
- Add non-regression test vector `negative/rekey_keypair_non_latest`: CreateKeyPair (EC P-256, FIPS masks), SetAttribute(RotateName), ReKeyKeyPair (gen-0→gen-1 succeeds), ReKeyKeyPair (gen-0 again) → "not the latest" error

- Fix KMIP lifecycle semantics: restore correct `setup_object_lifecycle` behavior — past `activation_date` → Active, `None` → PreActive ([#968](https://github.com/Cosmian/kms/pull/968))
- Add explicit `activation_date: Some(now)` to all request builders and test helpers requiring immediate Active state ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix KMIP spec reference: `§4.7` → `§4.8` in `rekey/common.rs` ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix KMIP spec reference: `§6.1.8` → `§6.1.45` for `ReCertify` operation ([#968](https://github.com/Cosmian/kms/pull/968))
- Add ownership check in `rewrap_dependants` to skip keys not owned by the caller ([#968](https://github.com/Cosmian/kms/pull/968))
- Simplify `relink_keys_to_new_certificate` by passing `old_cert_uid` directly instead of extracting from attributes ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `rewrap_dependants` losing `activation_date` metadata on Redis-findex: use attributes from `retrieve_object` instead of `find_wrapped_by` which fails on wrapped keys ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix KMIP 1.4 XML test cleanup: use Revoke + Destroy(remove:true) to fully purge stale objects from Redis-findex ([#968](https://github.com/Cosmian/kms/pull/968))
- Transfer `Name` attribute from old key to new key during ReKey per KMIP §4.4 ([#968](https://github.com/Cosmian/kms/pull/968))
- Return error instead of silently skipping when a user-supplied wrapping key ID equals the key being wrapped ([#968](https://github.com/Cosmian/kms/pull/968))
- Bypass ownership check for server-configured KEK during wrapping operations ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix symmetric ReKey missing server-wide KEK wrapping and unwrapped-cache insert ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix keypair rekey not preserving WrappingKeyLink on replacement keys ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix symmetric rekey hardcoding `State::Active` — now uses `setup_object_lifecycle` for date-based state computation ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `setup_object_lifecycle` not storing `activation_date` for `PreActive` keys — offset-based activation scheduling now works correctly ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `ReCertify` request/response deserialization to KMIP 2.1 message handler ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `ReCertify.generate_replacement` passing empty user to `get_subject`/`get_issuer` — use certificate owner instead ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `ReCertify` not computing lifecycle state from offset — certificates with future activation_date are now `PreActive` ([#968](https://github.com/Cosmian/kms/pull/968))

## Refactor

- Reorganize ReKey modules into `rekey/` folder: `mod.rs`, `symmetric.rs`, `keypair.rs`, `common.rs`; move `ReCertify` handler to `operations/recertify.rs` ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `RekeyOperation` trait into `common.rs` with `execute_rekey()` orchestrator — shared 2-phase commit logic ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract 6 shared helpers into `common.rs`: `compute_replacement_dates`, `prepare_replacement_attributes`, `update_old_key_after_rekey`, `set_rotation_metadata_on_new_key`, `clear_rotation_flags_on_old_key`, `enforce_privileged_user` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `KeyRetirement` struct + `finalize_rekey` function in `common.rs` — shared Phase 2 logic ([#968](https://github.com/Cosmian/kms/pull/968))
- Move `compute_rotation_uid` and `rewrap_dependants` from `symmetric.rs` to `common.rs` ([#968](https://github.com/Cosmian/kms/pull/968))
- Convert `ReKeyKeyPair` to 2-phase commit (matching symmetric) to support dependant re-wrapping on public keys ([#968](https://github.com/Cosmian/kms/pull/968))
- Add default implementations to `RekeyOperation` trait for `detect_wrapping`, `persist_new_key`, `finalize_dependants`, and `rewrap_new_objects` ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `extract_rewrap_spec`, `extract_wrapping_key_uid`, and `retrieve_eligible_keys` into `common.rs` as shared helpers ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract shared `validate_no_crypto_param_change` into `common.rs` ([#968](https://github.com/Cosmian/kms/pull/968))
- Refactor `prepare_attributes` in `keypair.rs` — extract `finalize_replacement_key` helper ([#968](https://github.com/Cosmian/kms/pull/968))
- Move `setup_new_key` and `finalize_replacement_key` from keypair.rs to common.rs ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `preserve_wrapping_key_link` into common.rs ([#968](https://github.com/Cosmian/kms/pull/968))
- Split `rewrap_dependants` (70→25 lines) by extracting `rewrap_single_dependant` helper ([#968](https://github.com/Cosmian/kms/pull/968))
- Split `relink_keys_to_new_certificate` by extracting `relink_single_key` helper ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `enforce_create_permission` and `reject_protection_storage_masks` shared helpers into `key_ops` module ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `find-due-for-rotation` SQL into `query.sql` and `query_mysql.sql` using `rawsql::Loader` macros ([#968](https://github.com/Cosmian/kms/pull/968))
- Extract `find-wrapped-by` SQL into `query.sql` and `query_mysql.sql` using `rawsql::Loader` macros ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `PublicKey` variant to SQLite `find_wrapped_by` inline query ([#968](https://github.com/Cosmian/kms/pull/968))
- Implement `find_wrapped_by` for Redis-findex backend ([#968](https://github.com/Cosmian/kms/pull/968))

## Testing

- Add 6 non-regression test vectors for key rotation scenarios:
  `rekey_wrapping_key`, `rekey_wrapped_key`, `rekey_wrapping_key_with_links`,
  `rekey_wrapping_key_double_chain`, `kek_rekey_wrapped`, `rekey_wrapped_deactivated` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 9 symmetric ReKey test vectors (basic, wrapped, wrapping-key re-wrap, name transfer, offset, links) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 27 ReKeyKeyPair test vectors (RSA, EC, ML-KEM, ML-DSA, SLH-DSA, X25519, secp256k1) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add Covercrypt ReKeyKeyPair test vector (in-place attribute rekey with same UIDs) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add access privilege escalation test vector for ReKey ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 4 ReCertify test vectors (self-signed, chain, with-links, with-offset) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 3 negative ReCertify test vectors (missing UID, non-existent, not a certificate) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 2 offset state verification vectors (rekey + rekey-keypair: Offset=0 → Active, Offset=86400 → PreActive) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 2 negative state restriction vectors: `rekey_preactive_fails`, `rekey_keypair_preactive_fails` ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `wrap_and_cache`: skip server-wide KEK wrapping for HSM-resident keys (UID has `hsm::` prefix) — they are hardware-protected and the wrapping step caused a self-wrap error when the key being created IS the configured KEK ([#968](https://github.com/Cosmian/kms/pull/968))
- Add vector `test_data/vectors/hsm/kek_bootstrap_self_create` + `server_type = "hsm_kek_uncreated"` server type to reproduce and prevent regressions of the HSM self-wrap bug ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 7 keyset resolution test vectors: `keyset_encrypt_latest`, `keyset_encrypt_bare_name`, `keyset_encrypt_latest_after_rotation`, `keyset_decrypt_try_each`, `keyset_decrypt_double_rotation`, `keyset_decrypt_at_latest`, `keyset_rotate_name_at_rejected` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add HSM keyset support: `find_due_for_rotation` on HsmStore reads `CKA_START_DATE`/`CKA_END_DATE`; keyset metadata stored in `CKA_LABEL` (`name::gen::key_id[::latest]`); `SetAttribute rotate_name` writes `CKA_LABEL` via `C_SetAttributeValue`; `SetAttribute rotate_interval` writes `CKA_START_DATE`/`CKA_END_DATE`; `Re-Key` on HSM UIDs generates a new HSM key and updates both CKA_LABELs; `walk_keyset_chain` resolves HSM keysets by `CKA_LABEL` without `ReplacedObjectLink` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add 3 HSM keyset test vectors: `resident_keyset_set_rotate_name`, `resident_keyset_rekey_and_decrypt`, `resident_keyset_double_rotation` + 1 negative: `hsm_rotate_offset_rejected` ([#968](https://github.com/Cosmian/kms/pull/968))

## Documentation

- Add key auto-rotation specification document covering all 6 rotation
  scenarios (plain symmetric, wrapping key, wrapped key, asymmetric pair,
  wrapped private key, server-wide KEK), rotation policy attributes,
  server-side scheduler, KMIP attribute tables, and implementation roadmap ([#968](https://github.com/Cosmian/kms/pull/968))
- Correct HSM key rotation section: the KMS cannot use KMIP `Re-Key` on
  HSM-managed keys (no SQL attribute storage, non-extractable key material);
  use PKCS#11 vendor tools instead ([#968](https://github.com/Cosmian/kms/pull/968))
- Document `x-rotate-generation` and `x-rotate-date` invariants: monotonically
  increasing counter unique within a key-set, authoritative last-rotation
  timestamp relied on by `is_due_for_rotation` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add Certificate Renewal (ReCertify) section to key_auto_rotation.md with RFC references ([#968](https://github.com/Cosmian/kms/pull/968))

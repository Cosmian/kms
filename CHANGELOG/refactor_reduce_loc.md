# Changelog — refactor/reduce_loc

## Refactor

- **KMIP operations**: replace repetitive `fmt::Display` / `fmt::Debug` `impl` blocks with `impl_display!` and `debug_from_display!` macros in `crate/kmip/src/kmip_2_1/kmip_operations.rs` and `crate/kmip/src/kmip_1_4/kmip_operations.rs` (~330 lines saved)
- **KMIP 1.4 types**: replace manual `From`/`TryFrom` enumerations with declarative macros in `crate/kmip/src/kmip_1_4/kmip_types.rs` (~301 lines saved)
- **Server attribute operations**: extract shared `match_add_attribute!`, `match_set_attribute!`, `match_delete_attribute!` macros into new `crate/server/src/core/operations/attribute_ops_dispatch.rs`, eliminating duplicated match arms across `add_attribute.rs`, `set_attribute.rs`, `modify_attribute.rs`, `delete_attribute.rs` (~1 126 lines saved)
- **Server lifecycle helpers**: extract `setup_object_lifecycle()`, `fill_missing_cp_fields()`, `merge_crypto_params()` into new `crate/server/src/core/operations/state_utils.rs`, removing duplication between `create.rs`, `create_key_pair.rs`, `import.rs`, and `register.rs` (~165 lines saved)
- **Web UI**: extract shared `useActionState` hook (`ui/src/hooks/useActionState.ts`) and `ActionResponse` component (`ui/src/components/common/ActionResponse.tsx`) used by all 66 action components, removing duplicated state management and response rendering code (~3 177 lines saved across the UI actions layer)
- **WASM client**: extract shared helper macros into `crate/clients/wasm/src/macros.rs`

**Net result**: 72 files changed, 5 002 deletions, 1 825 insertions (−3 177 net lines).

- **Pivot functions — oracle selection**: extract `select_eligible_oracle_uid()` into `state_utils.rs`, unifying the duplicate "Phase 1 oracle key selection" blocks in `encrypt.rs` and `sign.rs` (~30 lines saved)
- **Pivot functions — Azure EKM wrap/unwrap**: extract `kmip_encrypt_dek()` and `kmip_decrypt_dek()` into `crate/server/src/routes/azure_ekm/handlers.rs`, unifying duplicated KMIP `Encrypt`/`Decrypt` construction in `wrap_with_aes`+`wrap_with_rsa` and `unwrap_with_aes`+`unwrap_with_rsa` (~50 lines saved)
- **Decrypt key selection**: apply Phase 1+2 deterministic key-selection pattern to `decrypt.rs` — oracle-eligible keys dispatched via `select_eligible_oracle_uid`, DB keys via `select_unique_key_for_operation`
- **Signature verify key selection**: apply Phase 2 key-selection pattern to `signature_verify.rs` with PQC algorithm dispatch
- **Lifecycle guard**: extract `check_process_window()` helper into `state_utils.rs`, replacing inline ProcessStartDate/ProtectStopDate checks in `encrypt.rs`, `decrypt.rs`, and `sign.rs`
- **Auth guard**: extract `user_can_perform_operation()` helper into `state_utils.rs`, deduplicating authorization checks in `destroy.rs` and `revoke.rs`
- **PQC dispatch**: extract `resolve_key_algorithm()` and `is_pqc_signature_algorithm()` helpers into `state_utils.rs`, replacing duplicated 15-variant PQC match blocks in `sign.rs` and `signature_verify.rs`
- **MAC modernization**: rewrite `mac.rs` with Phase 2 key selection, lifecycle gating, and extracted `hmac_algorithm_to_hashing`/`infer_hmac_hashing_algorithm` helpers

## Security

- **KEK wrapping bypass via attribute operations**: fix a security bug where `ModifyAttribute`, `SetAttribute`, `AddAttribute`, and `Activate` would auto-unwrap HSM-wrapped keys via `retrieve_object_for_operation()` and then persist the unwrapped key material back to the database, defeating KEK encryption at rest. The fix skips auto-unwrapping for `GetAttributes`-type operations since they only need object metadata, not key material ([#960](https://github.com/Cosmian/kms/issues/960))

## Bug Fixes

- **Synology DSM + HSM-wrapped keys**: add `default_unwrap_type = ["SecretData", "SymmetricKey"]` to the HSM KEK vector test server, reproducing the exact configuration from issue #960 where DSM fails to retrieve keys wrapped by a hardware KEK ([#960](https://github.com/Cosmian/kms/issues/960))
- **Logging repetition in KMIP routes**: remove `span.enter()` calls from async route handlers in `routes/kmip.rs` that caused span names to repeat 70+ times in trace output when concurrent requests shared worker threads; per-operation instrumentation already exists in `core/kms/kmip.rs`

## Testing

- **Synology DSM vectors**: add GetAttributeList, GetAttributes, and Get steps to the Synology DSM integration vector to exercise the full key retrieval flow after Activate (requires `server_type = "hsm_kek"` with `HSM_SLOT_ID`)
- **Synology DSM Rust test**: extend `test_synology_dsm_volume_lifecycle` with GetAttributeList, GetAttributes, and Get operations matching the post-Activate DSM sequence

Closes #960

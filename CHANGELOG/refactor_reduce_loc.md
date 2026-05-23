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

## Features

- Add `activate` subcommand to all key/certificate/secret-data/opaque-object modules (`ckms sym keys activate`, `ckms ec keys activate`, `ckms rsa keys activate`, `ckms pqc keys activate`, `ckms cc keys activate`, `ckms certificates activate`, `ckms secret-data activate`, `ckms opaque-object activate`)

## Refactor

- Move `ActivateKeyAction` to `shared/activate.rs` — single struct reused by all 8 subcommand modules (symmetric, EC, RSA, PQC, Covercrypt, certificates, secret-data, opaque-object)
- Remove 10 per-module activate files and the `define_activate_key_action!` macro — replaced by the shared struct
- Remove dead shared `encrypt.rs` and `decrypt.rs` (never imported)
- Remove `save_kms_cli_config` / `force_save_kms_cli_config` / `SAVE_CONFIG_LOCK` from all 45 test files in ckms, replaced by `owner_config(ctx)` utility
- Retain `force_save_kms_cli_config` in `utils/config.rs` for auth tests requiring dynamic server configs (JWT, cert-auth, API tokens)
- Add `run_ckms` and `run_ckms_expect_error` helpers in `ckms/src/tests/utils/run.rs`
- Add `load_client_config` utility in `ckms/src/tests/utils/config.rs` for template-based test config loading with dynamic port patching
- Add convenience helpers `owner_config()` and `user_config()` for default test configs
- Delete ported tests from `cosmian_kms_cli_actions` (clap): `discover_versions`, `query`, `rng`, `mac_verify`, `opaque_object/`, `elliptic_curve/`, `rsa/`, `secret_data/`, `security/{access_control,lifecycle,privilege_bypass,uid_injection}`, `error_messages/activate`
- Add `push_link!` macro in `attributes/set.rs` to eliminate repetitive link-attribute construction
- Add `print_query_list`/`print_query_count`/`print_query_value` helpers in `kms_actions.rs` for Query display
- Extract `parse_x509_to_object()` helper for certificate import (PEM/DER deduplication)
- Extract `resolve_key_from_options()` shared helper for wrap/unwrap key source resolution
- Split `derive_key/mod.rs` into `resolve_base_key_id()`, `build_derivation_params()`, `parse_derivation_method()`
- Convert all `ckms` tests from `CreateKeyAction` struct instantiation to pure CLI string args (`&[&str]`), removing direct dependency on clap action structs in binary-level tests
- Extract `resolve_kek_wrapping_params()` for AWS BYOK export key material
- Split `google/key_pairs/create.rs` into `resolve_key_pair()`, `resolve_certificate()`, `push_to_gmail()`
- Add `symmetric/cipher_io.rs` with shared helpers: `resolve_aad()`, `build_cipher()`, `generate_dek()`
- Add `prompt_optional!`, `prompt_password!`, `prompt_required!` macros to ckms configure wizard

## Testing

- Port KMIP activate lifecycle tests to ckms CLI-level (`error_messages/activate.rs`): success, object-not-found, already-active, deactivated, destroyed, compromised, EC keys, RSA keys
- Port key lifecycle security tests to ckms CLI-level (`security/lifecycle.rs`): new-key-exportable, revoked-exportable-by-owner, destroyed-not-exportable, destroy-active-fails, double-revoke, double-destroy
- Port cross-user access control tests to ckms CLI-level (`security/access_control.rs`): user-cannot-export, user-cannot-revoke, user-cannot-destroy, grant-allows-export, revoke-grant-removes-access, user-cannot-self-grant
- Port privilege bypass tests to ckms CLI-level (`security/privilege_bypass.rs`): privileged-can-create, non-privileged-cannot-create, revoke-grant-denies-access, privilege-no-read-bleed
- Port UID injection tests to ckms CLI-level (`security/uid_injection.rs`): SQL injection, path traversal, wildcard, JSON injection
- Port `discover_versions`, `query`, `rng` tests to ckms CLI-level
- Port MAC verify test to ckms CLI-level (`mac.rs`)
- Port opaque object CRUD test to ckms CLI-level (`opaque_object/opaque_crud.rs`)
- Enable `test_set_attribute` module in ckms tests (was missing from `mod.rs`): covers `attributes get`, `attributes set`, `attributes delete` CLI commands
- Remove dead test files `aws_xks_tests.rs` and `digested.rs` (broken imports, never compiled)

## Bug Fixes

- Remove stale `x509-parser` dev-dependency from `cosmian_kms_cli_actions` (unused, bloated lockfile)
- Fix `test_issue_746_name_attribute_on_secret_data` assertion: use `NameValue` (PascalCase) to match actual KMIP JSON serialization

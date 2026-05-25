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
- **Generic crypto dispatch**: introduce `CryptoOpSpec` trait with associated types (`Request`, `Response`) and `perform_crypto_operation<Op>()` generic entry point, unifying all 6 crypto operations (Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify) into a single code path for key resolution, oracle routing, policy enforcement, usage-limit accounting, and clone-before-unwrap security ([#959](https://github.com/Cosmian/kms/pull/959))

## Security

- **KEK wrapping bypass via attribute operations**: fix a security bug where `ModifyAttribute`, `SetAttribute`, `AddAttribute`, and `Activate` would auto-unwrap HSM-wrapped keys via `retrieve_object_for_operation()` and then persist the unwrapped key material back to the database, defeating KEK encryption at rest. The fix skips auto-unwrapping for `GetAttributes`-type operations since they only need object metadata, not key material ([#960](https://github.com/Cosmian/kms/issues/960))
- **KEK plaintext leak via UsageLimits persist in Decrypt/Sign** (COSMIAN-2026-015): `decrypt.rs` and `sign.rs` unwrapped the key material in-place via `unwrap_and_enforce_policy`, then `decrement_usage_limits` persisted the plaintext key back to the database when UsageLimits were configured, silently stripping KEK encryption at rest. Fixed by cloning before unwrapping (same pattern already used in `encrypt.rs`) so `decrement_usage_limits` always persists the original wrapped object ([#959](https://github.com/Cosmian/kms/pull/959))
- **Attribute-mutation authorization bypass**: `SetAttribute`, `ModifyAttribute`, `AddAttribute`, and `DeleteAttribute` were all calling `retrieve_object_for_operation` with `KmipOperation::GetAttributes`, which uses a relaxed "any permission" check. Any authorized user (e.g. Encrypt-only) could therefore mutate object attributes. Fixed by passing the correct KMIP operation type for each operation; `retrieve_object_for_operation` now skips auto-unwrapping for all four attribute-mutating operations (not just `GetAttributes`). Added `SetAttribute`, `ModifyAttribute`, `AddAttribute`, and `DeleteAttribute` variants to `KmipOperation`. ([#959](https://github.com/Cosmian/kms/pull/959))
- **KMIP compliance — attribute ops on Compromised objects**: the `state_allows` guard in `retrieve_object_utils.rs` now permits `AddAttribute`, `ModifyAttribute`, `SetAttribute`, and `DeleteAttribute` on `Compromised`-state objects. KMIP spec allows attribute mutation regardless of lifecycle state (SKFF-M-9-14 / SKFF-M-9-21 test vectors verify this).

## Features

- **HSM key creation guard**: reject `Create`/`CreateKeyPair`/`Atomic` requests with an `hsm::` UID prefix when no HSM store is registered, preventing silent routing to the SQL backend (`database_objects.rs::get_object_store`) ([#959](https://github.com/Cosmian/kms/pull/959))
- **Agent instructions**: add mandatory per-prompt checklist to `.github/copilot-instructions.md` (CHANGELOG, test vectors, clippy, tests, docs); convert `AGENTS.md` from real file to symlink → `.github/copilot-instructions.md` so all three names (`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`) resolve to the same canonical source ([#959](https://github.com/Cosmian/kms/pull/959))

## Testing

- **HSM key without HSM plugin**: new negative test vector `test_data/vectors/negative/lifecycle/create_hsm_key_without_hsm` asserts that creating an `hsm::*` key on a non-HSM server returns `"No HSM is configured"` ([#959](https://github.com/Cosmian/kms/pull/959))
- **Unit test**: `cosmian_kms_server_database::core::database_objects::tests::test_hsm_uid_rejected_without_hsm_store` verifies the guard at the database routing layer ([#959](https://github.com/Cosmian/kms/pull/959))
- **HSM Crypt2Pay permissions**: fix tests #25 and #27 in `crate/server/src/tests/hsm/permissions.rs` to accept `Kmip21Error(Sensitive, "DENIED")` as a valid outcome when the HSM hardware enforces non-extractable keys ([#959](https://github.com/Cosmian/kms/pull/959))
- **KEK wrapping regression tests** (COSMIAN-2026-015): add `test_decrypt_preserves_kek_wrapping_with_usage_limits` and `test_sign_preserves_kek_wrapping_with_usage_limits` in `security_regression.rs` that create a KEK-wrapped key with UsageLimits, perform Decrypt/Sign, then verify the raw DB object is still wrapped ([#959](https://github.com/Cosmian/kms/pull/959))
- **Synology DSM vectors**: add GetAttributeList, GetAttributes, and Get steps to the Synology DSM integration vector to exercise the full key retrieval flow after Activate (requires `server_type = "hsm_kek"` with `HSM_SLOT_ID`)
- **Synology DSM Rust test**: extend `test_synology_dsm_volume_lifecycle` with GetAttributeList, GetAttributes, and Get operations matching the post-Activate DSM sequence
- **Access control privilege escalation vectors**: add 3 new test vectors exercising privilege escalation attacks — self-grant (owner grants self), non-owner grant (user tries to grant on owner's key), and destroy without permission (user with only Get attempts Destroy). Moved `fips/access_control/revoke` → `access_control/revoke_key_lifecycle` (not FIPS-specific) ([#959](https://github.com/Cosmian/kms/pull/959))
- **Dynamic port allocation**: extract `allocate_dynamic_port()` in `test_server.rs` and apply it to `start_test_kms_server_with_config()`, preventing port conflicts when multiple test servers run in parallel ([#959](https://github.com/Cosmian/kms/pull/959))
- **Grant all operation types (CLI)**: add `test_grant_all_operation_types` in `crate/clients/clap/src/tests/access.rs` — regression guard that grants all 22 `KmipOperation` variants (including attribute ops) and verifies they appear in `ListAccessesGranted`, preventing recurrence of the `set_attribute` serialisation bug ([#959](https://github.com/Cosmian/kms/pull/959))
- **Grant all operation types (E2E)**: add Playwright test `grant access with every operation type succeeds` in `access-rights-flow.spec.ts` that iterates all 21 UI-exposed operations and verifies each grant request returns `successfully added`; search uses only the first word of each operation label to avoid Ant Design Select treating the Space keypress as "select highlighted option" ([#959](https://github.com/Cosmian/kms/pull/959))
- **ESLint exclude Playwright artifacts**: add `test-results/**` and `playwright-report/**` to `ignores` in `ui/eslint.config.js` — ESLint was crashing with `ENOENT: no such file or directory, scandir 'test-results/.playwright-artifacts-N/traces'` when stale artifact directories had partially-deleted contents from interrupted runs ([#959](https://github.com/Cosmian/kms/pull/959))
- **E2E test timeouts for slow tests under parallel load**: set `test.setTimeout(180_000)` on three tests that exceed the default 90 s limit when 10 workers share a single SQLite-backed KMS server — `cert-lifecycle decrypt with wrong key fails` (two RSA key-pair creations), `locate-attributes all located objects have a valid Type` (no-filter Locate + full-table pagination), and `locate-hsm no-filter Locate includes HSM keys` (same); also add `earlyExitCount` parameter to `collectHsmKeysAcrossPages` so tests that only verify presence stop paginating as soon as the required count is reached ([#959](https://github.com/Cosmian/kms/pull/959))

## Bug Fixes

- **Synology DSM + HSM-wrapped keys**: add `default_unwrap_type = ["SecretData", "SymmetricKey"]` to the HSM KEK vector test server, reproducing the exact configuration from issue #960 where DSM fails to retrieve keys wrapped by a hardware KEK ([#960](https://github.com/Cosmian/kms/issues/960))
- **Logging repetition in KMIP routes**: remove `span.enter()` calls from async route handlers in `routes/kmip.rs` that caused span names to repeat 70+ times in trace output when concurrent requests shared worker threads; per-operation instrumentation already exists in `core/kms/kmip.rs`
- **Web UI Access operations list**: `AccessGrant` and `AccessRevoke` forms had a hardcoded list of only 8 KMIP operations; replaced with a WASM-exported `get_kmip_operations()` that dynamically provides all 21 delegable operations from the `KmipOperation` enum, ensuring the UI always stays in sync with the server ([#959](https://github.com/Cosmian/kms/pull/959))
- **WASM grant access serialisation**: `get_kmip_operations()` used `KmipOperation::to_string()` (Display, returns snake_case e.g. `set_attribute`) for the form value instead of the serde-lowercase representation the server expects (`setattribute`); fixed by using `serde_json::to_string(op)` — resolves HTTP 400 `unknown variant 'set_attribute'` error on grant/revoke for attribute operations ([#959](https://github.com/Cosmian/kms/pull/959))

## Security Documentation

- **COSMIAN-2026-015**: add SECURITY.md entry for KEK plaintext leak via UsageLimits persist in Decrypt/Sign (assigned correct ID — previously incorrectly referenced as COSMIAN-2026-006 in code and CHANGELOG) ([#959](https://github.com/Cosmian/kms/pull/959))
- **COSMIAN-2026-016**: add SECURITY.md entry for attribute-mutation authorization bypass (fixed in 5.23.0) ([#960](https://github.com/Cosmian/kms/issues/960))
- **Vulnerability ID corrections**: fix incorrect `COSMIAN-2026-005` references (lines 53/90/146/181 of `security_regression.rs`) → `COSMIAN-2026-014`; fix incorrect `COSMIAN-2026-006` references (lines 229/359 of `security_regression.rs` and line 140 of `crypto_op.rs`) → `COSMIAN-2026-015`

## Documentation

- **Authorization**: add `set_attribute`, `modify_attribute`, `add_attribute`, `delete_attribute` to the delegable operations table in `documentation/docs/configuration/authorization.md` ([#959](https://github.com/Cosmian/kms/pull/959))
- **HSM operations**: sync `documentation/docs/hsm_support/hsm_operations.md` with `authorization.md` — add `export`, `get_attributes`, `locate`, `mac`, `set_attribute`, `modify_attribute`, `add_attribute`, `delete_attribute` to the "Grantable operations" and "Operations by role" tables; fix `Verify` → `SignatureVerify` naming ([#959](https://github.com/Cosmian/kms/pull/959))

## CI

- **Freeze Python deps for JOSE tests**: add `.github/scripts/test/requirements-jose.txt` pinning `jwcrypto==1.5.6` and `cryptography<45.0.0`; update `test_jose.sh` to use `pip install -r` instead of bare install ([#959](https://github.com/Cosmian/kms/pull/959))
- **Fix argparse `-` prefix bug**: use `--flag="${VAR}"` (equals syntax) for all base64url arguments passed to `jose_interop_helper.py` to prevent Python argparse from misinterpreting ciphertexts or signatures that start with `-` as option flags

Closes #960

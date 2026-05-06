## [Unreleased]

### 🚀 Features

#### HSM — simultaneous multiple HSM instances

- **`[[hsm_instances]]` TOML config**: new array-of-tables section in `kms.toml` allows configuring any number of HSM instances simultaneously. Each entry specifies `model`, `admin`, `slot`, and `password`. When this section is present it takes precedence over the legacy flat `--hsm-*` CLI flags.
- **Prefix-based routing**: the first `[[hsm_instances]]` entry gets the routing prefix `"hsm"`, the second `"hsm1"`, the third `"hsm2"`, etc. Object UIDs follow the pattern `<prefix>::<slot_id>::<key_id>`.
- **`HsmBackend` prefix-aware**: `HsmBackend::new()` now accepts an explicit `prefix: &str` argument. `parse_uid` uses this prefix to strip the correct routing prefix from incoming UIDs.
- **`GLOBAL_HSMS`**: the internal singleton for test-server reuse is now a `Vec` of `Arc<dyn HSM>` (one entry per configured instance) rather than a single optional value.
- **`GET /hsm/status` endpoint**: new public HTTP endpoint (no authentication required) returning a JSON array of all connected HSM instances with their prefix, model, and per-slot accessibility info.
- **Web UI — HSM Status page**: new `Objects → HSM Status` page that calls `/hsm/status` and displays each HSM instance in a card with a slot table, accessible via the `hsm-status` menu entry.
- **Web UI — `Locate.tsx` prefix regex**: all hard-coded `uid.startsWith("hsm::")` checks replaced with `/^hsm[0-9]*::/.test(uid)` so multi-HSM UIDs (`hsm1::`, `hsm2::`, etc.) are handled correctly throughout the Locate page.
- **`resources/kms.toml`**: added commented-out example of `[[hsm_instances]]` blocks.

#### HSM — model-based routing prefix

- **HSM UID prefix now includes model name**: the HSM object UID format changed from `hsm::<slot>::<key>` (with numeric suffixes `hsm1::`, `hsm2::` for multi-HSM) to `hsm::<model>::<slot>::<key>` (e.g. `hsm::utimaco::0::my_aes_key`, `hsm::softhsm2::0::kek`). When duplicate models are configured, the second instance gets `hsm::<model>_1`, the third `hsm::<model>_2`, etc.
- **`has_prefix()` rewritten**: prefix detection in `uid_utils.rs` now parses the `hsm::<model>::` pattern instead of splitting on the first `::`.
- **`as_hsm_uid!` macro updated**: now takes 3 arguments `($model, $slot, $key)` instead of 2.
- **UI `Locate.tsx`**: HSM detection regex updated from `/^hsm[0-9]*::/` to `/^hsm::/`.
- **Shell scripts and TOML configs**: all hardcoded `hsm::0::` references updated to include the model name.

### 🐛 Bug Fixes

- **HSM permissions tests: fix hardcoded slot 0**: the `permissions.rs` test file used `as_hsm_uid!(0, ...)` instead of reading the configured HSM slot from the test config. This caused "slot 0 is not accessible" failures on SoftHSM2 where slot IDs are dynamically assigned. Fixed all 5 occurrences to use the slot from `hsm_clap_config()`.
- **HSM object listing: handle `CKR_ATTRIBUTE_TYPE_INVALID`**: externally-provisioned HSM objects (e.g. a server KEK imported directly into the HSM without `CKA_ID` / `CKA_LABEL`) previously caused a spurious error in `call_get_attributes` because `CKR_ATTRIBUTE_TYPE_INVALID` was not explicitly handled. It now returns `Ok(None)` (attribute absent) instead of `Err(…)`, so these objects are silently skipped in the object-listing path instead of being logged as errors. The `kms_hsm::find()` loop also now logs the actual error message when an object cannot be identified.
- **`HsmBackend::retrieve()` — sensitive-key fallback restored**: the migration from `HsmStore` to `HsmBackend` accidentally dropped the issue #933 fix that falls back to `get_key_metadata()` when `export()` fails because the key is non-extractable (sensitive). The fallback now builds a metadata-only stub object so `ModifyAttribute`/`GetAttributes` succeed without touching key material. ([#942](https://github.com/Cosmian/kms/pull/942))
- **`HsmBackend::update_object()` — return `Ok(())` for attribute updates**: `update_object` was returning `Err(...)` causing `ModifyAttribute`/`SetAttribute` to fail on every HSM key. HSM PKCS#11 slots do not support KMIP attribute storage; the correct behaviour is to accept the call silently (with a warning log) and return `Ok(())`. ([#942](https://github.com/Cosmian/kms/pull/942))
- **`HsmBackend::find()` and `atomic()` — use `self.prefix` for UID generation**: the generated UIDs in `find()` and `atomic()` hardcoded `"hsm::"` instead of using `self.prefix`. This broke multi-HSM setups where the prefix can be `"hsm::softhsm2"`, `"hsm::utimaco"`, etc. ([#942](https://github.com/Cosmian/kms/pull/942))
- **`database_objects::get_object_store` — longest-prefix matching**: the function used `split_once("::")` to extract the routing prefix, which always returned only the first segment (e.g. `"hsm"`) and therefore routed UIDs like `"hsm::softhsm2::0::key"` to the legacy `"hsm"` backend instead of the correct `"hsm::softhsm2"` one. Fixed to use longest-prefix matching across all registered stores. ([#942](https://github.com/Cosmian/kms/pull/942))
- **`HsmBackend::atomic()` — handle `UpdateObject`-only batches**: after exporting or getting an HSM key, `export_get.rs` calls `database.atomic()` with a single `UpdateObject` to persist the `fresh=false` flag. `HsmBackend::atomic()` previously only handled RSA keypair creation and returned an error for any other batch, causing export/get to fail with `InvalidRequest`. It now detects all-`UpdateObject` batches and delegates each to `update_object()` (which already accepts such calls gracefully). ([#942](https://github.com/Cosmian/kms/pull/942))
- **`user_has_permission()` — `Get`↔`Export` equivalence for HSM keys**: HSM keys require each KMIP operation to be granted explicitly (no `Get`-as-wildcard). This meant a user granted `Get` could not `Export` an HSM key and vice versa, even though both operations read the same key material. Added equivalence logic so holding either `Get` or `Export` grants access for both operations on HSM keys. ([#942](https://github.com/Cosmian/kms/pull/942))
- **HSM permissions test cleanup — revoke before destroy**: `symmetric_key_create_request` sets `activation_date = now`, making newly-created keys Active. KMIP enforces that Active keys must be revoked before they can be destroyed. The test teardown in scenario #31 now calls `revoke_key()` before `Destroy` to comply with the KMIP lifecycle state machine. ([#942](https://github.com/Cosmian/kms/pull/942))

### 🧪 Testing

- **`crate/server/src/tests/hsm/multi_hsm.rs`**: new `#[ignore]` test (`test_multi_hsm_routing`) verifying that two `[[hsm_instances]]` entries each create and locate keys under the correct prefix.
- **`test_kms_server`**: added `ONCE_SERVER_WITH_MULTI_HSM` singleton and `start_default_test_kms_server_with_multi_softhsm2()` helper starting a KMS server with two `HsmInstanceConfig` entries (port `DEFAULT_KMS_SERVER_PORT + 8`).
- **`test_kms_server`**: added `ONCE_SERVER_WITH_THREE_SOFTHSM2` singleton and `start_default_test_kms_server_with_three_softhsm2()` — starts a KMS server with a legacy single-HSM config (slot 1) **and** two `[[hsm_instances]]` entries (slots 2 and 3) at port `DEFAULT_KMS_SERVER_PORT + 9`. Slot IDs are read from `HSM_SLOT_ID_1/2/3` env vars at runtime.
- **`BuildServerParamsOptions`**: new `hsm_instances: Vec<HsmInstanceConfig>` field; when non-empty it overrides the legacy `hsm: Option<HsmConfig>` field when building `ClapConfig`. Both fields can now coexist simultaneously.
- **`crate/clients/ckms/src/tests/hsm/multi_softhsm2.rs`**: new `#[ignore]` test `test_multi_hsm_key_creation_test` exercising AES-256 key creation and destruction across 3 SoftHSM2 slots using all three UID prefix conventions (legacy `hsm::`, new `hsm::softhsm2::`, disambiguated `hsm::softhsm2_1::`).
- **`.github/scripts/test/test_hsm_softhsm2.sh`**: initialises 3 SoftHSM2 tokens (`my_token_1/2/3`), exports `SOFTHSM2_HSM_SLOT_ID/2/3`, and invokes the new `test_multi_hsm_key_creation_test`.
- **`ui/tests/e2e/hsm-multi-keys.spec.ts`**: new Playwright spec — creates and destroys AES-256 keys on 3 HSM slots via the UI using the legacy, new, and disambiguated UID prefixes; slot IDs provided by `PLAYWRIGHT_HSM_SLOT_ID_1/2/3`.
- **`.github/scripts/test/test_ui.sh`**: initialises 3 SoftHSM2 tokens, configures the KMS server with `hsm:` (slot 1) + `[[hsm_instances]]` (slots 2 and 3), pre-creates one HSM key per slot, and passes `PLAYWRIGHT_HSM_SLOT_ID_1/2/3` to Playwright.

### 📚 Documentation

- **Documentation**: new `documentation/docs/hsm_support/multi_hsm.md` page explaining routing, TOML config, and the `/hsm/status` endpoint.
- **Documentation**: `hsm_operations.md` updated with new UID format.
- **Documentation**: `hsm_operations.md` — added "HSM key authorization model" section with two permission tables (operations by role, grantable operations) and updated Destroy description to reflect admin-only enforcement.

### 🔒 Security

#### HSM key permissions hardening

- **Admin-only Destroy**: HSM key destruction is now restricted to HSM admins only. Non-admin users cannot destroy HSM keys even if they were previously granted the `Destroy` operation. ([#942](https://github.com/Cosmian/kms/pull/942))
- **Block Destroy/Revoke grants**: granting `Destroy` or `Revoke` operations on HSM keys is now rejected with an explicit error. These operations are reserved for HSM admins. ([#942](https://github.com/Cosmian/kms/pull/942))
- **Remove Get-as-wildcard for HSM keys**: the `Get` permission no longer implicitly grants all other operations (`Encrypt`, `Decrypt`, `Sign`, etc.) on HSM keys. Each operation must be granted individually. ([#942](https://github.com/Cosmian/kms/pull/942))
- **Locate visibility filtering**: non-admin users no longer see HSM keys in Locate results unless they have been explicitly granted at least one operation on those keys. ([#942](https://github.com/Cosmian/kms/pull/942))
- **`/access/owned` visibility filtering**: `HsmBackend::find()` now returns an empty list when `user_must_be_owner=true` and the caller is not an HSM admin, preventing HSM key leakage through the `/access/owned` REST endpoint. ([#942](https://github.com/Cosmian/kms/pull/942))
- **32 non-regression test scenarios**: new `crate/server/src/tests/hsm/permissions.rs` with comprehensive test coverage for HSM key authorization (Create, Destroy, Locate, Grant/Revoke, Encrypt/Decrypt, Get/Export, Sign, server KEK). ([#942](https://github.com/Cosmian/kms/pull/942))

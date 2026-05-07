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

- **HSM object listing: handle `CKR_ATTRIBUTE_TYPE_INVALID`**: externally-provisioned HSM objects (e.g. a server KEK imported directly into the HSM without `CKA_ID` / `CKA_LABEL`) previously caused a spurious error in `call_get_attributes` because `CKR_ATTRIBUTE_TYPE_INVALID` was not explicitly handled. It now returns `Ok(None)` (attribute absent) instead of `Err(…)`, so these objects are silently skipped in the object-listing path instead of being logged as errors. The `kms_hsm::find()` loop also now logs the actual error message when an object cannot be identified.

### 🧪 Testing

- **`crate/server/src/tests/hsm/multi_hsm.rs`**: new `#[ignore]` test (`test_multi_hsm_routing`) verifying that two `[[hsm_instances]]` entries each create and locate keys under the correct prefix.
- **`test_kms_server`**: added `ONCE_SERVER_WITH_MULTI_HSM` singleton and `start_default_test_kms_server_with_multi_softhsm2()` helper starting a KMS server with two `HsmInstanceConfig` entries (port `DEFAULT_KMS_SERVER_PORT + 8`).
- **`BuildServerParamsOptions`**: new `hsm_instances: Vec<HsmInstanceConfig>` field; when non-empty it overrides the legacy `hsm: Option<HsmConfig>` field when building `ClapConfig`.

### 📚 Documentation

- **Documentation**: new `documentation/docs/hsm_support/multi_hsm.md` page explaining routing, TOML config, and the `/hsm/status` endpoint.
- **Documentation**: `hsm_operations.md` updated with new UID format.

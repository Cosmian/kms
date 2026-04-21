## [Unreleased]

### 🚀 Features

#### PQC X.509 Certificates

- **Server — PQC X.509 certificate issuance**: the `Certify` operation now supports ML-DSA-44/65/87 and all SLH-DSA variants (SHA2 / SHAKE × 128s/f / 192s/f / 256s/f) as both subject key algorithms and issuer signing keys (non-FIPS only). The digest selection in `build_and_sign_certificate` previously used the subject's key type and fell through to `SHA-256` for PQC keys; it now correctly uses the issuer's signing key type and maps any non-RSA/EC key (EdDSA, ML-DSA, SLH-DSA) to `MessageDigest::null()` (internal digest).
- **CLI — PQC algorithms in `certificates certify --algorithm`**: the `Algorithm` enum in `certificate_utils` now includes all ML-DSA (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) and SLH-DSA variants as valid `--algorithm` values for `--generate-key-pair` mode (non-FIPS only).
- **Web UI / WASM — PQC algorithms in Certificate Certify form**: `get_certificate_algorithms()` now includes all ML-DSA and SLH-DSA algorithm options (non-FIPS only), so the *Generate New Keypair* dropdown in the Certificate Certify form exposes all PQC signing algorithms.
- **CLI tests — full PQC algorithm coverage for certificate generation**: added `fetch_pqc_certificate` helper (using `x509_parser` instead of the OpenSSL bindings so PQC OIDs are handled correctly) and `certify_pqc_self_signed` shared helper; added 15 new `#[tokio::test]` cases covering self-signed certificates for every PQC signing algorithm (ML-DSA-65/87, SLH-DSA-SHA2-128s/f, SLH-DSA-SHA2-192s/f, SLH-DSA-SHA2-256s/f, SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-192s/f, SLH-DSA-SHAKE-256s/f) plus a cross-algorithm test (SLH-DSA CA signing an ML-DSA leaf).

#### Key auto-rotation (scheduled / policy-driven)

- **KMIP link chain**: `ReKey` now creates a fresh key UUID and links old and new keys via `ReplacementObjectLink` / `ReplacedObjectLink` attributes, enabling full rotation lineage tracking ([#859](https://github.com/Cosmian/kms/issues/859)).
- **Wrapping-key rotation**: when a wrapping key is rotated, all objects it protects are automatically re-wrapped with the new key and their `WrappingKeyLink` attribute is updated.
- **Wrapped-key rotation**: symmetric keys that are themselves wrapped are transparently unwrapped, re-keyed, then re-wrapped with the same wrapping key during rotation.
- **Database query `find_due_for_rotation`**: all DB backends (SQLite, PostgreSQL, MySQL, Redis-Findex) can now query for keys whose `RotateInterval` has elapsed since the last `RotateDate`.
- **Auto-rotation background task**: a new `run_auto_rotation()` operation scans all owned objects due for rotation and rotates them automatically; each rotation is counted in the `kms.key.auto_rotation` OTel metric. Supported object types: `SymmetricKey` (via `ReKey`), `Certificate` (via `Certify` upsert/re-sign), `PrivateKey` / `PublicKey` (via `ReKeyKeyPair` — currently CoverCrypt only; RSA/EC key pair rotation is gracefully skipped with a warning until `ReKeyKeyPair` is extended).
- **Cron wiring**: the background cron thread now schedules auto-rotation checks at a configurable interval (default: disabled, set `--auto-rotation-check-interval-secs` > 0 to enable).
- **CLI `set-rotation-policy`**: new `sym keys set-rotation-policy` sub-command to configure `--interval`, `--name`, and `--offset` rotation attributes on any symmetric key.
- **CLI `--rotate-interval/--rotate-name/--rotate-offset` on create**: all create commands (`sym keys create`, `rsa keys create-key-pair`, `ec keys create-key-pair`, `pqc keys create-key-pair`, `cc keys create-master-key-pair`) now accept optional `--rotate-interval`, `--rotate-name`, and `--rotate-offset` flags to set the rotation policy at key creation time.
- **CLI `re-key` subcommand for RSA, EC, PQC**: `rsa keys re-key`, `ec keys re-key`, and `pqc keys re-key` subcommands added (symmetric re-key was already present); they accept `--key-id` and an optional `--offset` parameter. Server-side support for asymmetric `ReKey` will follow in a subsequent PR.
- **Web UI — Re-Key**: new `sym/keys/re-key` page allowing users to re-key a symmetric key from the browser; backed by new `rekey_ttlv_request` / `parse_rekey_ttlv_response` WASM bindings. Re-Key is also added to RSA, EC, PQC, and Covercrypt menus.
- **Web UI — Rotation Policy at creation**: all Create forms (Symmetric, RSA, EC, PQC, Covercrypt master key) and the **Certificate Certify/Renew** form now include a collapsible *Auto Rotation Policy* panel with interval, name, and offset fields applied via `SetAttribute` after creation.
- **Web UI — Set Rotation Policy removed**: the standalone *Set Rotation Policy* menu item has been removed from all key type menus; rotation policy is now set inline in the Create form.
- **Web UI — Covercrypt Re-Key**: new `CovercryptReKey` component allowing re-keying a Covercrypt master key pair by access policy; backed by new `rekey_cc_keypair_ttlv_request` / `parse_rekey_cc_keypair_ttlv_response` WASM bindings (non-FIPS only).
- **Web UI menus unified**: all key type menus (Symmetric, RSA, EC, PQC, Covercrypt) now share the same structure: Create → Re-Key → Export → Import → Revoke → Destroy.
- **Server flag `--auto-rotation-check-interval-secs`**: configures (or disables) the server-side background rotation check interval.

- **Rotation lineage in key names**: when a key has a user-defined UID (non-UUID format, e.g. `"toto"`), auto-rotation now generates the new key UID as `"toto_<uuid>"` instead of a random UUID, preserving lineage traceability across the rotation chain. On subsequent rotations the old UUID suffix is stripped so the pattern stays `"toto_<new_uuid>"` rather than accumulating segments (e.g. `"toto_<uuid1>_<uuid2>"`).
- **Server KEK bypass for `wrap_using_kms`**: the ownership check in `wrap_using_kms` now skips the permission check when the wrapping key is the server-configured `key_encryption_key` (server KEK), mirroring the existing bypass in `wrap_using_crypto_oracle`. This fixes auto-rotation failures when all keys are wrapped by a non-HSM server KEK.
- **`rekey`: fix TTLV re-wrapping error for rotated wrapped keys**: after generating fresh key material, the re-wrapping step now overrides `encoding_option = NoEncoding` for symmetric keys (whose bytes are always recoverable). Previously, inheriting `TTLVEncoding` from the old key's wrapping data caused the TTLV serialiser to fail on Cosmian-proprietary attributes (`RotateDate`, etc.) embedded in the new key's `KeyValue::Structure`.

- **HSM object listing: handle `CKR_ATTRIBUTE_TYPE_INVALID`**: externally-provisioned HSM objects (e.g. a server KEK imported directly into the HSM without `CKA_ID` / `CKA_LABEL`) previously caused a spurious error in `call_get_attributes` because `CKR_ATTRIBUTE_TYPE_INVALID` was not explicitly handled. It now returns `Ok(None)` (attribute absent) instead of `Err(…)`, so these objects are silently skipped in the object-listing path instead of being logged as errors. The `kms_hsm::find()` loop also now logs the actual error message when an object cannot be identified.
- **Locate page — Date column**: added `initial_date` to the date fallback chain (priority: last rotation date → `initial_date` → activation date → original creation date); keys with `initial_date` set now always show a date. HSM-resident keys (no date in PKCS#11) display `HSM` with a tooltip rather than a bare `—`.

### 🐛 Bug Fixes

- **Auto-rotation: RSA/EC `CreateKeyPair` fails in FIPS mode with `CryptographicUsageMask = None`**: `create_rsa_key_pair` (crypto crate) reads the usage mask exclusively from `private_key_attributes.cryptographic_usage_mask` and `public_key_attributes.cryptographic_usage_mask`, ignoring `common_attributes`. `rotate_asymmetric_keypair` was passing `None` for both per-key attributes, so the FIPS validation rejected the request with *"forbidden CryptographicUsageMask value, got None"*. Fixed by pre-resolving the old public key UID (via `PrivateKeyLink` on the old private key) and fetching the old public key's `cryptographic_usage_mask`, then constructing explicit `private_key_attributes` and `public_key_attributes` structs with the correct masks for the `CreateKeyPair` request.
- **Auto-rotation: new RSA/EC/PQC key pair created Active (not PreActive)**: after `rotate_asymmetric_keypair` creates the new key pair, both the new private key and the new public key were left in `PreActive` state because `create_key_pair` defaults to `PreActive` unless an explicit `activation_date` is provided. The atomic update for both new keys now explicitly sets `state = Active` and `activation_date = now`, matching the behaviour of `rekey` for symmetric keys.
- **Auto-rotation: full RSA/EC/PQC key pair rotation when triggered via public key**: previously, when the rotation policy was set on the public key, `run_auto_rotation` delegated to `auto_rotate_key` for the private key, which failed with `Item_Not_Found` for RSA keys because `rekey_keypair` only supported CoverCrypt. The `PublicKey` path now directly calls `rotate_asymmetric_keypair`, which creates a new key pair and atomically clears `rotate_interval = 0` on BOTH old keys. The rotation policy is captured from the public key's attributes (not the private key's, which may have no policy), so the cadence is correctly preserved on the new private key regardless of which key carried the policy.

#### Key rotation policy semantics

- **Auto-rotation: old key's `rotate_interval` now set to `0` after rotation**: previously the old key's `rotate_interval` was left unchanged after `run_auto_rotation`, causing the cron to re-pick the same object on the next check. After rotation, `rekey.rs` now explicitly writes `rotate_interval = Some(0)` to the old key's metadata, preventing the cron from rotating it a second time.
- **Auto-rotation: new key now inherits rotation policy from old key**: after `run_auto_rotation` completes an auto-triggered rekey, `auto_rotate.rs` now captures the old key's `rotate_interval`, `rotate_name`, and `rotate_offset` before calling `rekey`, then writes them to the new key along with a fresh `initial_date`. This ensures the auto-rotation cadence is preserved seamlessly across generations without any manual operator intervention.
- **Manual rekey: new key does NOT inherit rotation policy**: when a user explicitly calls `Re-Key`, the new key starts with `rotate_interval = Some(0)` (disabled). This is intentional — a manual rekey is an out-of-cycle operator action; the operator should explicitly re-arm the rotation policy on the new key if desired. The old key also gets `rotate_interval = Some(0)`.

#### UI — Locate page

- **Locate: fix Type and Key Format Type showing N/A for all keys**: after enriching locate results with `GetAttributes` per object, a redundant inner try/catch block was calling `supplementStateFromOwned(mapped, ...)` using the un-enriched `mapped` array (with `ObjectType: undefined`) and overwriting the correctly populated `merged` data. The inner block is removed — `supplementStateFromOwned(enriched, ...)` already produces the correct final rows.
- **Locate: fix pagination not working when changing page size**: the `pageSize` prop on the `Table` pagination was a controlled value that reset to 10 on every render, ignoring user selection. Changed to `defaultPageSize` (uncontrolled) so Ant Design's internal state handles changes correctly.
- **Locate: add Date column**: a sortable *Date* column is added to the results table showing the best available date for each object (priority: last rotation date → creation/initial date → activation date). The column header indicates the date source via a tooltip.
- **Locate: add inline Auto-Rotate button**: each row in the results table now has a compact *Auto-Rotate* button in the Actions column. When auto-rotation is already configured the button shows a blue tag with the current interval (e.g. `↻ 30d`); clicking it opens a Popover to update the interval (in days) or disable it. Disabling sets `rotate_interval = 0` via `SetAttribute`, which causes `is_due_for_rotation` to return `false`. The `initial_date` attribute is also now supported in `parse_selected_attributes_flatten` so it can be fetched and displayed.
- **`parse_selected_attributes_flatten`: add `initial_date` support**: the Rust attribute parser in `crate/client_utils/src/attributes_utils.rs` now handles the `"initial_date"` key, returning its Unix timestamp so the UI can display it as a date source.

#### Key rotation policy attributes not visible after creation

- **Server `GetAttributes`**: rotation policy fields (`rotate_interval`, `rotate_name`, `rotate_offset`, `rotate_date`, `rotate_generation`, `rotate_latest`) are Cosmian-proprietary extensions that have no standard KMIP `Tag` enum values. They were never included in `GetAttributes` responses because the Tag-based iteration loop had no matching arms for them. Fixed by copying these fields from the stored `Attributes` directly into the response struct after the Tag loop.
- **WASM `parse_selected_attributes_flatten`**: the `match` in `parse_selected_attributes_flatten` fell through to `_x => {}` when any rotate_* attribute was specifically requested by name. Added explicit match arms for all six rotation fields.
- **UI Attribute Get page**: added `rotate_interval`, `rotate_name`, `rotate_offset`, `rotate_date`, `rotate_generation`, `rotate_latest` to the `ATTRIBUTE_NAMES` selector so users can retrieve them individually.

#### Configuration

- **`auto_rotation_check_interval_secs` ignored in TOML config**: the field was placed under the `[ui_config]` section in the test config, but it is a top-level `ClapConfig` field and must appear before any section header to be parsed correctly. Moved to the top level in `test_data/configs/server/ui.toml`.

#### Key rotation correctness, `RotateLatest=false` on old key**: the flag was previously copied verbatim from the old key to the new one, making it impossible to locate the most recently rotated key via `Locate` with `rotate_latest=true` (KMIP §4.51). Now exactly one key in a lineage carries `rotate_latest=true` at any point in time

#### Certificate auto-renewal reliability

- **Certificate renewal now creates new objects instead of overwriting**: auto-rotation for certificates previously upserted a re-signed cert in place (same UID). The certificate, private key, and public key are now left unchanged; a completely new set of objects (new cert UID + new key pair UIDs) is created on each renewal. The old objects receive a `ReplacementObjectLink` pointing to their successors; the new objects carry a `ReplacedObjectLink` back to their predecessors (KMIP 2.1 §4.48 semantics). The old cert's rotation policy (`rotate_interval`, `rotate_date`, `initial_date`) is cleared after renewal so the cron does not pick it up again. The new cert inherits the rotation policy so subsequent renewals continue at the configured cadence.
- **Certificate renewal produces bitwise-identical DER bytes (renewals appear silent)**: the serial number was computed as `SHA1(SPKI)`, which is deterministic and unchanged across renewals of the same key pair. RSA PKCS#1 v1.5 signing is also deterministic, so the entire X.509 DER was identical before and after renewal. Users saw *"certificate xxx re-certified"* in logs but the certificate file appeared unchanged. Fixed by mixing the current nanosecond timestamp into the SHA1 hash (`sha1.update(&OffsetDateTime::now_utc().unix_timestamp_nanos().to_le_bytes())`) so consecutive renewals produce unique serial numbers per RFC 5280 §4.1.2.2.
- **`PrivateKeyLink`/`PublicKeyLink` lost after renewal**: `build_and_sign_certificate` stripped `PrivateKeyLink` and `PublicKeyLink` from the certificate attributes (to prevent issuer-key leakage) but never restored them for `Subject::Certificate` (renewal). After the first auto-renewal the cert had no key links, causing all subsequent cron renewals to fail with *"No private or public key link found for the certificate"*. Fixed by splitting the `Subject::X509Req | Subject::Certificate` match arm and restoring the subject certificate's key links from the stored attributes after signing.
- **`rotate_date` not updated after certificate renewal**: `auto_rotate.rs` contained a wrong comment claiming *"rotate_date is set by the certify path"*, but `build_and_sign_certificate` never updates it. This made `is_due_for_rotation` return `true` on every cron tick (since the old past date was reused), causing the cert to be renewed indefinitely. Fixed by explicitly setting `certify_attrs.rotate_date = Some(OffsetDateTime::now_utc())` before the `Certify` call in `auto_rotate_key`.
- **`initial_date` never set on newly issued certificates**: `is_due_for_rotation` computes the first rotation deadline as `initial_date + rotate_interval` when no `rotate_date` exists. Because `certify/mod.rs` never stamped `initial_date` on new certificates, any cert created with only `rotate_interval` set (the typical production flow) was silently skipped on every cron tick — users saw *"Running scheduled key auto-rotation check"* in logs with no renewal. Fixed by setting `attributes.initial_date = Some(OffsetDateTime::now_utc())` in `build_and_sign_certificate` when it is not already present (preserves the original date across renewals).

- **`rekey`: clear stale `link` from new-key attrs before `create_symmetric_key_and_tags`**: links from the source key were embedded in the new key's block and shadowed the correct links stored in the metadata column, causing chained-rekey assertions to fail.
- **`rekey`: clear `key_format_type` from new-key attrs**: the `Raw` presentation format passed to the key generator caused "unable to generate a symmetric key for format: Raw" when rekeying keys with `GetAttributes`-normalised format type.
- **`rekey`: commit new wrapping key before re-wrapping dependants**: the new wrapping key is now persisted in a Phase-1 atomic commit before any wrapped-key re-wrapping occurs, fixing "wrapping key not found" errors during wrapping-key rotation.

### 🧪 Testing

- **`test_auto_rotation_public_key_triggers_full_rsa_keypair_rotation`**: new server-side unit test that sets a rotation policy on the *public* key of an RSA pair and verifies that `run_auto_rotation` creates a new, active RSA key pair in FIPS mode without a usage-mask error.
- **Server**: 25 unit tests covering basic rekey, KMIP link chain, rotation metadata propagation, policy preservation, `rotate_latest` flag, wrapped/wrapping-key rotation, chained rotations, unknown-uid errors, all `run_auto_rotation` edge cases, certificate renewal (new-object semantics with `ReplacementObjectLink`/`ReplacedObjectLink`), public-key graceful-skip (RSA key pair rekey not yet implemented), two **end-to-end cron tests** that verify the background thread fires autonomously, a **production-scenario test** (`test_cron_renews_cert_with_only_rotate_interval_set`) that guards against the `initial_date`-missing regression, `test_cert_auto_rotation_updates_der_bytes` which asserts the new cert's DER bytes differ from the old cert's, the old cert is preserved unchanged, and all cross-links are correct, and **4 new wrapped-key rotation tests** (tests 26-29): `SetAttribute` on wrapped symmetric/RSA-private keys, `WrappingKeyLink` preservation after rekey, and full auto-rotation end-to-end flow for wrapped symmetric keys.
- **CLI (ckms + cosmian_kms_cli)**: updated `test_rekey_symmetric_key` to assert `id != id_2`; added 4 `set-rotation-policy` CLI tests validating `--interval`, `--name`, `--offset`, and disable-by-zero semantics; added `test_rekey_sets_link_chain_after_rotation_policy` CLI test verifying that after setting a rotation policy and manually rekeying, old key carries `ReplacementObjectLink` → new key and new key carries `ReplacedObjectLink` → old key; added `test_set_rotation_policy_on_wrapped_key` CLI test verifying `SetAttribute` succeeds on a key stored wrapped (ByteString key block); added `rotation_kek.rs` with `#[ignore = "Requires SoftHSM2"]` integration test verifying `set-rotation-policy` works against a KEK-protected KMS server.
- **Server**: added `test_auto_rotation_transfers_policy_to_new_key` unit test verifying that auto-rotation (cron-triggered) sets `rotate_interval=0` on the old key and transfers the full rotation policy (`rotate_interval`, `rotate_name`) to the new key.
- **Web UI E2E**: added `set rotation policy then re-key` Playwright test confirming that arming a key with a rotation policy, rekeying via the UI, and then fetching attributes on the old key all succeed — the old key's `ReplacementObjectLink` points to the new key UID.
- **Server-side self-wrapping rejection**: `wrap_and_cache` now returns `KmsError::InvalidRequest` when `wrapping_key_id == unique_identifier` (user-supplied), preventing a key from being created with itself as wrapping key; genuine server-KEK coincidences are logged as a warning and silently skipped.
- **Full E2E lifecycle test for symmetric key auto-rotation** (`set_rotation_policy.rs`): `test_symmetric_key_auto_rotation_lifecycle` validates the complete flow — key creation, `SetAttribute(RotateInterval)`, wait for cron, verify `ReplacementObjectLink`/`ReplacedObjectLink` links, compare raw key bytes (must differ), verify rotation policy is transferred from old to new key.
- **Self-wrapping rejection test** (`set_rotation_policy.rs`): `test_self_wrapping_key_is_rejected` confirms the server rejects a `Create` request with `wrapping_key_id == key_id`.
- **KEK lifecycle test** (`rotation_kek.rs`): `test_kek_wrapped_key_auto_rotation_lifecycle` (`#[ignore]`) mirrors the symmetric lifecycle test for keys held under a `SoftHSM2` KEK — verifies raw bytes differ after auto-rotation, correct KMIP links, and re-wrapping by the same KEK.
- **New `rotation_rsa.rs`**: `test_rsa_wrapped_sym_key_auto_rotation_lifecycle` tests an AES key wrapped by an RSA public key through full auto-rotation — verifies `WrappingKeyLink` preserved on the new key, and RSA ciphertext differs between old and new key.
- **New `rotation_cert.rs`**: `test_certificate_auto_rotation_lifecycle` verifies X.509 certificate auto-renewal using `compare_cert_rotation_x509()` — asserts DER bytes differ, serial number changes, subject CN preserved, and public key material differs (new key pair generated).
- **`rekey`: fix `cryptographic_algorithm = None` crash for wrapped keys during auto-rotation**: after `wrap_object()` the key value becomes an opaque `ByteString` and `Object::attributes()` returns an error; the subsequent `unwrap_or_default()` previously produced empty `Attributes`, losing `cryptographic_algorithm`, causing subsequent auto-rotations to fail with *"the cryptographic algorithm must be specified for secret key creation"*. Fixed by capturing attributes from the new object BEFORE wrapping and falling back to them when the post-wrap `attributes()` call fails.
- **`rekey`: update `wrapping_key_id` vendor attribute on dependants**: when a wrapping key rotates, all keys it protects are re-wrapped with the new key. The `WrappingKeyLink` was already updated but the Cosmian vendor attribute `wrapping_key_id` was not. Fixed by calling `set_wrapping_key_id(new_uid)` alongside `set_link(WrappingKeyLink, new_uid)` for each re-wrapped dependant.
- **Rotation lifecycle tests: adjust timing to prevent double-rotation flakiness**: RSA and certificate rotation tests now use an 8 s interval and 12 s wait (previously 4 s / 10 s). After the first rotation, the new key inherits the rotation policy and becomes due again 8 s later, safely after the 12 s assertion window closes (next rotation at t ≈ 16 s).

### 🔨 Build / Refactor

#### Internalize `cosmian_kms_logger`

- **`crate/logger`**: `cosmian_kms_logger` is now a first-class workspace member at `crate/logger/` instead of being pulled from crates.io. The source is identical to `cosmian_kms_logger 0.5.4` with the following adaptations for the workspace:
    - Removed `std::env::set_var` calls (unsafe in edition 2024) — the `rust_log` string from `TracingConfig` is now fed directly to `EnvFilter::try_new()`, removing the need to mutate the process environment.
    - Fixed all clippy lints enforced by the workspace (`struct_excessive_bools`, `items_after_statements`, `manual_inspect`, `unnecessary_debug_formatting`, `str_to_string`, `let_underscore_drop`).
    - `opentelemetry 0.29.x` packages are pinned directly in the crate manifest (workspace uses 0.27 for the server metrics layer; both versions coexist in the dependency tree).

### 📚 Documentation

#### Key auto-rotation policy

- Added [`documentation/docs/kmip_support/key_auto_rotation.md`](../documentation/docs/kmip_support/key_auto_rotation.md): comprehensive reference for the scheduled key rotation feature covering all key types (plain, wrapping, wrapped, asymmetric), lifecycle diagrams (Mermaid stateDiagram + sequenceDiagram + flowchart), KMIP attribute table, and configuration examples.
- **Documentation: auto-rotation vs manual-rekey semantics**: updated the `key_auto_rotation.md` attribute table to clearly distinguish auto-rotation (old key gets `rotate_interval=0`; new key **inherits** the policy) from manual rekey (old key gets `rotate_interval=0`; new key also gets `rotate_interval=0` — user must explicitly re-arm the new key).
- **Documentation: wrapped-key and KEK sections**: added two new sections to `key_auto_rotation.md` — *§5 Wrapped private key (CoverCrypt)* (documents `SetAttribute` compatibility and notes RSA/EC limitation) and *§6 Server-wide key-encryption key (KEK)* (explains transparent KEK wrapping via SoftHSM2/Utimaco and provides shell example); updated §4 header to clarify it covers plain asymmetric keys; rewired the Mermaid `flowchart TD` dispatch diagram to include all dispatched object types.
- **Documentation: fix Mermaid `\n` in diagram labels**: all `\n` escape sequences in Mermaid `stateDiagram` and `flowchart` node labels were replaced with single-line labels or `<br/>` (for notes in `sequenceDiagram`), preventing literal `\n` characters from appearing in rendered diagrams.
- Added entry in `documentation/mkdocs.yml` under *KMIP Support → Key Auto-Rotation Policy*.
- Updated `README.md` *Why Cosmian KMS* section with a one-line summary and link.

#### Authentication — Break-Glass / Local Authentication

- Added *Break-Glass / Local Authentication* section to [`documentation/docs/configuration/authentication.md`](../documentation/docs/configuration/authentication.md): documents the operational best practice of configuring TLS client certificate authentication alongside OIDC/JWT so that administrators retain a local, out-of-band recovery path when the identity provider is unreachable. Includes step-by-step certificate issuance, server configuration, ckms CLI usage, and emergency recovery procedures.

#### Renewal notification system

- **`NotificationsStore` trait**: new `?Send` trait with five methods (`create_notification`, `list_notifications`, `count_unread`, `mark_read`, `mark_all_read`) backed by a per-backend SQL table (`notifications`); implemented for SQLite, PostgreSQL, and MySQL; Redis uses a dedicated `NoopNotificationsStore`.
- **`rotate_last_warning_days` attribute**: new optional Cosmian-extension field on `Attributes` tracking the largest warning threshold (in days) for which a renewal-approaching notification has already been dispatched, preventing duplicate warnings across cron cycles.
- **`dispatch_renewal_warnings` cron function**: new `auto_rotate.rs` function called after `run_auto_rotation` on every cron tick; scans objects due for rotation within the configured warning window, compares against `rotate_last_warning_days`, creates a DB notification, and sends an e-mail via the optional SMTP notifier.
- **Notification HTTP routes**: four actix-web endpoints registered at `/api/notifications` — `GET /` (list), `GET /count-unread` (badge), `POST /{id}/read`, `POST /read-all`.
- **Web UI — Notifications**: `NotificationBell` component in the main header displays a live unread badge (polling via `useNotifications` hook); clicking it opens an Ant Design `<Popover>` showing the last 10 notifications inline (tag, message, timestamp, Mark all read); a *View all →* link navigates to `/notifications` for the full list.
- **SMTP configuration**: `SmtpConfig` + `NotificationsConfig` wired from the server config/CLI layer through `ServerParams` to `KMS::instantiate()` where an `EmailNotifier` is constructed when SMTP parameters are present.
- **`EmailNotifier`: real SMTP delivery via `lettre`**: replaced the no-op stub implementation with a full `lettre 0.11` STARTTLS client. `send_rotation_success`, `send_rotation_failure`, and `send_renewal_warning` now send structured plain-text emails with key details (UID, type, algorithm, generation, owner, timestamps, error message). No feature flag is required — SMTP delivery is compiled in by default and silently disabled when no SMTP host is configured.
- **Removed `email-notifications` feature flag**: the flag is no longer referenced anywhere in the codebase, documentation, or test fixtures. SMTP support is unconditional; runtime behaviour is controlled solely by whether `KMS_SMTP_HOST` (or `[notifications.smtp].host`) is set.
- **Web UI — merged *Re-Key* + *Set Rotation Policy* pages**: the standalone *Set Rotation Policy* page has been removed for all five key types (Symmetric, RSA, EC, PQC, Covercrypt). Rotation policy configuration is now embedded directly in the *Re-Key* page as a collapsible second card. Old `/*/keys/set-rotation-policy` routes have been removed.

### 🔒 Security

- **SMTP password no longer logged at startup**: `SmtpConfig` previously derived `Debug`, causing the plaintext SMTP password to appear in server startup logs (`info!("KMS Server configuration: {server_params:#?}")`). Replaced the derived `Debug` impl with a hand-written one that emits `"<redacted>"` for the `password` field.

### ⚠️ Known Limitations

- **Auto-rotation idempotency (single-node only)**: the current implementation prevents double-rotation within a single node by setting `rotate_interval = 0` on the old key as part of the rotation atomic batch. This guard is not CAS-atomic at the database level (no `UPDATE … WHERE rotate_interval > 0` conditional write). In a **multi-node deployment** where two KMS instances run the cron simultaneously, both may read the same due key and both attempt rotation before either commits the `rotate_interval = 0` update. For single-node deployments this is safe. A database-level CAS guard (`UPDATE objects SET attributes = … WHERE id = ? AND attributes->>'RotateInterval' > 0`) will be added in a follow-up issue.

---

## Multi-HSM support

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
- **Documentation**: new `documentation/docs/hsm_support/multi_hsm.md` page explaining routing, TOML config, and the `/hsm/status` endpoint.

### 🧪 Testing

- **`crate/server/src/tests/hsm/multi_hsm.rs`**: new `#[ignore]` test (`test_multi_hsm_routing`) verifying that two `[[hsm_instances]]` entries each create and locate keys under the correct prefix.
- **`test_kms_server`**: added `ONCE_SERVER_WITH_MULTI_HSM` singleton and `start_default_test_kms_server_with_multi_softhsm2()` helper starting a KMS server with two `HsmInstanceConfig` entries (port `DEFAULT_KMS_SERVER_PORT + 8`).
- **`BuildServerParamsOptions`**: new `hsm_instances: Vec<HsmInstanceConfig>` field; when non-empty it overrides the legacy `hsm: Option<HsmConfig>` field when building `ClapConfig`.
- **E2E — `certificates-certify.spec.ts`**: new Playwright spec with 27 tests covering all four certification methods and every supported algorithm:
    - Method 4 (generate new keypair): RSA-2048, RSA-4096, P-256, P-384, P-521, Ed25519, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/f/192s/256s, SLH-DSA-SHAKE-128s/256s; ML-KEM-512 self-sign rejected by server.
    - Method 2 (existing public key): EC P-256 self-signed; ML-DSA-44 self-signed.
    - Method 3 (re-certify): renews an existing certificate.
    - CA-issued: ML-KEM-512/768/1024 and RSA-4096 leaves issued by an ML-DSA-44 CA.
    - Optional certificate ID: custom UUID is preserved in the response.
    - PQC tests are automatically skipped in FIPS mode (`PLAYWRIGHT_FIPS_MODE=true`).
    - Added `createCertificate` helper to `helpers.ts` for reuse across test files.
    - Added `data-testid="cert-algorithm-select"` to the algorithm `<Select>` in `CertificateCertify.tsx`.

Closes #859

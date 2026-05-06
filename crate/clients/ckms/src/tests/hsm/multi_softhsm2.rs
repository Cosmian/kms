//! Multi-`SoftHSM2` key creation / destruction tests.
//!
//! These tests require a KMS server that is wired to **three** independent
//! `SoftHSM2` tokens:
//!
//! - Slot 1 (`HSM_SLOT_ID_1`) is handled by the legacy single-HSM config
//!   (`hsm:` TOML field). Keys are addressed with the **old** UID prefix
//!   `"hsm::<slot_id>::<key_id>"`.
//!
//! - Slot 2 (`HSM_SLOT_ID_2`) is the first entry in `[[hsm_instances]]`.
//!   Keys are addressed with `"hsm::softhsm2::<slot_id>::<key_id>"`.
//!
//! - Slot 3 (`HSM_SLOT_ID_3`) is the second entry in `[[hsm_instances]]`
//!   (same model as slot 2, so the KMS disambiguates it with suffix `_1`).
//!   Keys are addressed with `"hsm::softhsm2_1::<slot_id>::<key_id>"`.
//!
//! The test is invoked from `.github/scripts/test/test_hsm_softhsm2.sh` with
//! the three slot IDs set as environment variables.

use cosmian_kms_cli_actions::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use cosmian_logger::log_init;
use test_kms_server::{TestsContext, start_default_test_kms_server_with_three_softhsm2};
use uuid::Uuid;

use crate::{
    error::result::CosmianResult,
    tests::{
        save_kms_cli_config,
        shared::{ExportKeyParams, destroy, export_key},
        symmetric::create_key::create_symmetric_key,
    },
};

/// Read a usize slot ID from the named environment variable, defaulting to `fallback`.
fn slot_from_env(var: &str, fallback: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Create an AES-256 key on the given HSM slot using an explicit UID with the
/// provided routing prefix, then assert the key was actually stored by
/// attempting a (non-extractable) export, and finally destroy it.
///
/// The `uid_prefix` should be one of:
/// - `"hsm"` → old single-HSM format: `hsm::<slot>::<uuid>`
/// - `"hsm::softhsm2"` → new format for first model entry: `hsm::softhsm2::<slot>::<uuid>`
/// - `"hsm::softhsm2_1"` → disambiguated new format: `hsm::softhsm2_1::<slot>::<uuid>`
fn create_and_destroy_aes_key(
    cli_conf_path: &str,
    uid_prefix: &str,
    slot_id: usize,
) -> CosmianResult<()> {
    let key_uuid = Uuid::new_v4();
    let key_id = format!("{uid_prefix}::{slot_id}::{key_uuid}");

    println!("  Creating AES-256 key with UID: {key_id}");

    let returned_id = create_symmetric_key(
        cli_conf_path,
        CreateKeyAction {
            key_id: Some(key_id.clone()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            ..Default::default()
        },
    )?;

    // The server should echo back the requested UID.
    assert_eq!(
        returned_id, key_id,
        "server returned a different UID than requested: {returned_id}"
    );

    println!("  Created successfully, destroying …");
    // HSM keys must be removed from the HSM (remove = true).
    destroy(cli_conf_path, "sym", &key_id, true)?;

    // After destroy the key must be gone.
    let export_res = export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_owned(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/hsm_key_test".to_owned(),
        ..Default::default()
    });
    assert!(
        export_res.is_err(),
        "key {key_id} should not be exportable after destroy"
    );
    assert!(
        export_res
            .unwrap_err()
            .to_string()
            .contains("Object not found"),
        "unexpected error after destroy"
    );

    println!("  Destroyed successfully.");
    Ok(())
}

/// Test key creation and destruction across three `SoftHSM2` instances using
/// both the legacy UID prefix and the new model-qualified prefixes.
///
/// Slot IDs are read from `HSM_SLOT_ID_1`, `HSM_SLOT_ID_2`, `HSM_SLOT_ID_3`
/// environment variables (set by `test_hsm_softhsm2.sh`).
pub(crate) fn test_multi_hsm_key_creation(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(None);
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let slot1 = slot_from_env("HSM_SLOT_ID_1", 0);
    let slot2 = slot_from_env("HSM_SLOT_ID_2", 1);
    let slot3 = slot_from_env("HSM_SLOT_ID_3", 2);

    println!("=== Multi-SoftHSM2 key creation tests ===");
    println!("  Slot 1 (legacy prefix 'hsm'): {slot1}");
    println!("  Slot 2 (new prefix 'hsm::softhsm2'): {slot2}");
    println!("  Slot 3 (new prefix 'hsm::softhsm2_1'): {slot3}");

    // ── Slot 1: legacy hsm::<slot>::<key> prefix ─────────────────────────
    println!("\n[1/3] Legacy single-HSM prefix (slot {slot1})");
    create_and_destroy_aes_key(&owner_client_conf_path, "hsm", slot1)?;

    // ── Slot 2: new hsm::softhsm2::<slot>::<key> prefix ──────────────────
    println!("\n[2/3] New multi-HSM prefix 'hsm::softhsm2' (slot {slot2})");
    create_and_destroy_aes_key(&owner_client_conf_path, "hsm::softhsm2", slot2)?;

    // ── Slot 3: disambiguated hsm::softhsm2_1::<slot>::<key> prefix ──────
    println!("\n[3/3] Disambiguated multi-HSM prefix 'hsm::softhsm2_1' (slot {slot3})");
    create_and_destroy_aes_key(&owner_client_conf_path, "hsm::softhsm2_1", slot3)?;

    println!("\n=== All multi-SoftHSM2 key creation tests passed ===");
    Ok(())
}

/// Entry point invoked by `test_hsm_softhsm2.sh`.
#[ignore = "Requires three SoftHSM2 tokens (HSM_SLOT_ID_1/2/3)"]
#[tokio::test]
async fn test_multi_hsm_key_creation_test() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_three_softhsm2().await;
    test_multi_hsm_key_creation(ctx)
}

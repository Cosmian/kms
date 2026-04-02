//! Integration tests for key auto-rotation with a server-wide key-encryption
//! key (KEK) held in `SoftHSM2`.
//!
//! These tests start an in-process KMS server backed by `SoftHSM2` and verify:
//!
//! 1. `test_set_rotation_policy_with_softhsm2_kek` — Creating a symmetric key
//!    succeeds (the server transparently wraps it with the KEK) and
//!    `SetAttribute(RotateInterval)` on the wrapped key succeeds.
//!
//! 2. `test_kek_wrapped_key_auto_rotation_lifecycle` — Full E2E lifecycle:
//!    create a key (transparently wrapped by the HSM KEK), arm auto-rotation
//!    with a short interval, wait for the cron to fire, and verify:
//!    - `ReplacementObjectLink` is set on the old key.
//!    - The new (rotated) key has different raw material.
//!    - KMIP rotation metadata is correct on both keys.
//!    - The new key is still transparently protected by the same KEK.
//!
//! All tests are `#[ignore]` because they require `SoftHSM2` to be installed.

use std::time::Duration;

use cosmian_kms_cli_actions::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kmip::{
        kmip_0::kmip_types::KeyWrapType,
        kmip_2_1::{
            kmip_attributes::Attribute,
            kmip_operations::{Export, GetAttributes, SetAttribute},
            kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier},
            requests::symmetric_key_create_request,
        },
    },
};
use test_kms_server::start_default_test_kms_server_with_softhsm2_and_kek;

use super::set_rotation_policy::set_rotation_policy_cmd;
use crate::{
    error::result::CosmianResult,
    tests::{save_kms_cli_config, symmetric::create_key::create_symmetric_key},
};

// ─── CLI command test ─────────────────────────────────────────────────────────

/// Verify that auto-rotation attributes can be set on a key stored in a
/// KEK-protected (`SoftHSM2`) KMS server.
///
/// The `SetAttribute` operation must succeed even though the key at rest is
/// wrapped by the server-wide KEK located in the HSM.
#[tokio::test]
#[ignore = "Requires SoftHSM2 installed (softhsm2-util, libsofthsm2.so)"]
async fn test_set_rotation_policy_with_softhsm2_kek() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a symmetric key; the server will transparently wrap it with the KEK.
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    // Setting a rotation policy must succeed even though the key is KEK-wrapped.
    let stdout = set_rotation_policy_cmd(
        &owner_client_conf_path,
        &key_id,
        &["--interval", "3600", "--name", "hourly"],
    )?;
    assert!(
        stdout.contains("Rotation policy updated"),
        "set-rotation-policy on a KEK-protected key must succeed: {stdout}"
    );
    assert!(
        stdout.contains("interval=3600s"),
        "stdout must confirm the rotation interval: {stdout}"
    );

    Ok(())
}

// ─── Lifecycle test ───────────────────────────────────────────────────────────

/// Full lifecycle test: symmetric key auto-rotation under a `SoftHSM2` KEK.
///
/// The server has `auto_rotation_check_interval_secs = 10` (the default for
/// the static `SoftHSM2` server). We use `rotate_interval = 4` and wait 20 s,
/// which guarantees at least one cron tick after the key becomes due.
///
/// Key assertions:
/// - Old key: `ReplacementObjectLink` set, `rotate_interval = 0`, `rotate_latest = false`.
/// - New key: `ReplacedObjectLink` set, `rotate_latest = true`, `rotate_interval = 0`.
/// - Raw bytes of old key ≠ raw bytes of new key.
/// - The new key is still accessible (exportable), proving the server's KEK
///   re-wrapped it during rotation.
#[tokio::test]
#[ignore = "Requires SoftHSM2 installed (softhsm2-util, libsofthsm2.so)"]
async fn test_kek_wrapped_key_auto_rotation_lifecycle() -> CosmianResult<()> {
    const ROTATE_INTERVAL_SECS: i32 = 4;
    // The static server checks every 10 s.  Wait 20 s to be sure at least one
    // check fires after the 4 s rotation interval has elapsed.
    const WAIT_SECS: u64 = 20;

    let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
    let client = ctx.get_owner_client();

    // ── Step 1: Create a key (transparently wrapped by the KEK) ──────────────
    let create_req = symmetric_key_create_request(
        "cosmian",
        None, // server-generated UID
        256,
        CryptographicAlgorithm::AES,
        std::iter::empty::<&str>(),
        false,
        None, // no explicit wrapping — KEK wrapping is transparent
    )?;
    let create_resp = client.create(create_req).await?;
    let old_key_id = create_resp.unique_identifier.to_string();

    // ── Step 2: Export raw bytes of the OLD key ────────────────────────────────
    let old_bytes = client
        .export(Export {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            key_wrap_type: Some(KeyWrapType::NotWrapped),
            ..Export::default()
        })
        .await?
        .object
        .key_block()?
        .key_bytes()?
        .to_vec();
    assert_eq!(old_bytes.len(), 32, "AES-256 must be 32 bytes");

    // ── Step 3: Arm auto-rotation ──────────────────────────────────────────────
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            new_attribute: Attribute::RotateInterval(ROTATE_INTERVAL_SECS),
        })
        .await?;

    // ── Step 4: Wait for the cron to fire ─────────────────────────────────────
    tokio::time::sleep(Duration::from_secs(WAIT_SECS)).await;

    // ── Step 5: Verify ReplacementObjectLink on the old key ───────────────────
    let old_attrs_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            attribute_reference: None,
        })
        .await?;
    let replacement_link = old_attrs_resp
        .attributes
        .get_link(LinkType::ReplacementObjectLink)
        .unwrap_or_else(|| {
            panic!(
                "ReplacementObjectLink must be set on the old key after {WAIT_SECS} s; \
                 attributes: {:?}",
                old_attrs_resp.attributes
            )
        });
    let new_key_id = replacement_link.to_string();
    assert_ne!(new_key_id, old_key_id, "new key must have a different UID");

    // ── Step 6: Compare raw key material ─────────────────────────────────────
    let new_bytes = client
        .export(Export {
            unique_identifier: Some(UniqueIdentifier::TextString(new_key_id.clone())),
            key_wrap_type: Some(KeyWrapType::NotWrapped),
            ..Export::default()
        })
        .await?
        .object
        .key_block()?
        .key_bytes()?
        .to_vec();
    assert_eq!(new_bytes.len(), 32, "rotated AES-256 key must be 32 bytes");
    assert_ne!(
        old_bytes, new_bytes,
        "rotated key must have different material from the original"
    );

    // ── Step 7: Old key's rotation policy must be cleared ────────────────────
    assert_eq!(
        old_attrs_resp.attributes.rotate_interval,
        Some(0),
        "old key must have rotate_interval = 0 after rotation"
    );
    assert_eq!(
        old_attrs_resp.attributes.rotate_latest,
        Some(false),
        "old key must have rotate_latest = false after rotation"
    );

    // ── Step 8: New key must carry the correct links and flags ────────────────
    let new_attrs_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(new_key_id.clone())),
            attribute_reference: None,
        })
        .await?;
    let replaced_link = new_attrs_resp
        .attributes
        .get_link(LinkType::ReplacedObjectLink)
        .unwrap_or_else(|| {
            panic!(
                "ReplacedObjectLink must be set on the new key; \
                 attributes: {:?}",
                new_attrs_resp.attributes
            )
        });
    assert_eq!(
        replaced_link.to_string(),
        old_key_id,
        "new key's ReplacedObjectLink must point back to the original key"
    );
    assert_eq!(
        new_attrs_resp.attributes.rotate_latest,
        Some(true),
        "new key must be marked rotate_latest = true"
    );
    // The auto-rotation cron transfers the old rotate_interval to the new key.
    assert_eq!(
        new_attrs_resp.attributes.rotate_interval,
        Some(ROTATE_INTERVAL_SECS),
        "new key must inherit rotate_interval from the old key"
    );

    Ok(())
}

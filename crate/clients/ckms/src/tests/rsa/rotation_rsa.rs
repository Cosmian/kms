//! Lifecycle test for auto-rotation of an RSA-wrapped symmetric key.
//!
//! ## Scenario
//!
//! 1. Start a dedicated KMS server with `auto_rotation_check_interval_secs = 2`.
//! 2. Create an RSA-2048 key pair.
//! 3. Create a 256-bit AES key that is immediately wrapped by the RSA public key
//!    (using `wrapping_key_id`).
//! 4. Export the wrapped ciphertext of the original AES key.
//! 5. Arm auto-rotation: `SetAttribute(RotateInterval = 4)`.
//! 6. Wait 10 s — the cron fires at least twice and triggers `ReKey`.
//! 7. Verify `ReplacementObjectLink` on the old key.
//! 8. Verify the new (rotated) key is also wrapped by the same RSA public key
//!    (`WrappingKeyLink` still points to the RSA public key).
//! 9. Export wrapped ciphertext of the new key and compare to the old: they
//!    must differ (fresh AES material → different RSA-OAEP ciphertext).

use std::time::Duration;

use cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attribute,
    kmip_operations::{Export, GetAttributes, SetAttribute},
    kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier},
    requests::symmetric_key_create_request,
};
use test_kms_server::{
    AuthenticationOptions, BuildServerParamsOptions, ClientAuthOptions, MainDBConfig,
    ServerJwtAuth, ServerTlsMode, TestsContext, build_server_params_full, resolve_test_port,
    start_test_server_with_options,
};

use crate::{
    error::result::CosmianResult,
    tests::{
        rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
        save_kms_cli_config,
    },
};

// ─── Server helpers ───────────────────────────────────────────────────────────

/// Start a disposable KMS server with a fast auto-rotation cron
/// (`check_interval = 2 s`).  Uses `SQLite` with a fresh DB per port.
///
/// `preferred_port` is a hint; `resolve_test_port` falls back to a free OS-assigned
/// port if the preferred one is already in use.
async fn start_auto_rotation_server(preferred_port: u16) -> CosmianResult<TestsContext> {
    let port = resolve_test_port(preferred_port)?;
    let server_params = build_server_params_full(BuildServerParamsOptions {
        db_config: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            ..MainDBConfig::default()
        },
        port,
        tls: ServerTlsMode::PlainHttp,
        jwt: ServerJwtAuth::Disabled,
        auto_rotation_check_interval_secs: 2, // fast: check every 2 s
        ..BuildServerParamsOptions::default()
    })?;

    Ok(start_test_server_with_options(
        MainDBConfig::default(), // ignored — server_params is pre-built
        port,
        AuthenticationOptions {
            server_params: Some(server_params),
            client: ClientAuthOptions::default(),
        },
        None,
        None,
    )
    .await?)
}

// ─── Lifecycle test ───────────────────────────────────────────────────────────

/// Auto-rotation lifecycle for a symmetric key that is persistently wrapped by
/// an RSA public key.
///
/// After rotation the new key must:
/// - Have different ciphertext (and underlying key material) than the old key.
/// - Carry the same `WrappingKeyLink` pointing to the same RSA public key.
/// - Have `ReplacedObjectLink` pointing back to the old key.
#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_rsa_wrapped_sym_key_auto_rotation_lifecycle() -> CosmianResult<()> {
    const PORT: u16 = 10_102;
    const ROTATE_INTERVAL_SECS: i32 = 8;
    const WAIT_SECS: u64 = 12;

    let ctx = start_auto_rotation_server(PORT).await?;
    let (owner_conf_path, _) = save_kms_cli_config(&ctx);
    let client = ctx.get_owner_client();

    // ── Step 1: Create an RSA-2048 key pair ───────────────────────────────────
    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_conf_path,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;

    // ── Step 2: Create a 256-bit AES key wrapped by the RSA public key ────────
    let create_req = symmetric_key_create_request(
        "cosmian",
        None, // server-generated UID
        256,
        CryptographicAlgorithm::AES,
        std::iter::empty::<&str>(),
        false,
        Some(&public_key_id), // arm RSA wrapping at Create time
    )?;
    let create_resp = client.create(create_req).await?;
    let old_key_id = create_resp.unique_identifier.to_string();

    // ── Step 3: Export the RSA-wrapped ciphertext of the original AES key ─────
    let old_wrapped_bytes = client
        .export(Export {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            // No key_wrap_type → return key in its stored (wrapped) form
            ..Export::default()
        })
        .await?
        .object
        .key_block()?
        .wrapped_key_bytes()?
        .to_vec();
    assert!(
        !old_wrapped_bytes.is_empty(),
        "old wrapped ciphertext must not be empty"
    );

    // ── Step 4: Arm auto-rotation ──────────────────────────────────────────────
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            new_attribute: Attribute::RotateInterval(ROTATE_INTERVAL_SECS),
        })
        .await?;

    // ── Step 5: Wait for the cron to fire ─────────────────────────────────────
    tokio::time::sleep(Duration::from_secs(WAIT_SECS)).await;

    // ── Step 6: Verify ReplacementObjectLink on the old key ───────────────────
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

    // ── Step 7: Old key attributes ────────────────────────────────────────────
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

    // ── Step 8: New key – links and flags ─────────────────────────────────────
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
        "new key's ReplacedObjectLink must point to the original key"
    );

    // The new key must still be wrapped by the same RSA public key.
    let new_wrapping_link = new_attrs_resp
        .attributes
        .get_link(LinkType::WrappingKeyLink)
        .unwrap_or_else(|| {
            panic!(
                "WrappingKeyLink must be set on the new key; \
                 attributes: {:?}",
                new_attrs_resp.attributes
            )
        });
    assert_eq!(
        new_wrapping_link.to_string(),
        public_key_id,
        "new key must still be wrapped by the same RSA public key"
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

    // ── Step 9: Compare wrapped ciphertext ────────────────────────────────────
    let new_wrapped_bytes = client
        .export(Export {
            unique_identifier: Some(UniqueIdentifier::TextString(new_key_id.clone())),
            ..Export::default()
        })
        .await?
        .object
        .key_block()?
        .wrapped_key_bytes()?
        .to_vec();
    assert!(
        !new_wrapped_bytes.is_empty(),
        "new wrapped ciphertext must not be empty"
    );
    assert_ne!(
        old_wrapped_bytes, new_wrapped_bytes,
        "RSA-wrapped ciphertext must differ after rotation (new key material + RSA-OAEP randomization)"
    );

    Ok(())
}

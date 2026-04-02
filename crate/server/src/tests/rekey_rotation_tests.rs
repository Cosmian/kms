//! Comprehensive tests for the KMIP symmetric key rotation / `ReKey` feature.
//!
//! Covered scenarios
//! -----------------
//! 1. Basic rekey — fresh UID, new key material, old key unchanged.
//! 2. KMIP Link chain — `ReplacedObjectLink` on new key, `ReplacementObjectLink` on old key.
//! 3. Rotation metadata — `rotate_generation` increments, `rotate_date` is set.
//! 4. Rotation policy propagation — `rotate_interval`, `rotate_name`, `rotate_offset` copied.
//! 5. `rotate_latest` flag — new key gets true, old key gets false.
//! 6. Rekey a wrapped key — new key is re-wrapped with same wrapping key.
//! 7. Rekey a wrapping key — wrapped dependants are re-wrapped with the new key.
//! 8. Chained rekey — rotate twice, link chain grows correctly.
//! 9. Rekey non-existent key returns error.
//! 10. Auto-rotation `is_due_for_rotation` logic — due / not-due / disabled edge cases.
//! 11. `run_auto_rotation` rotates keys past their interval.
//! 12. `run_auto_rotation` does NOT rotate keys ahead of schedule.
//! 13. Set + Get rotation policy attributes via KMIP `SetAttribute`.
//! 14. Auto-rotation of a Certificate — creates new cert + key pair, links old → new via
//!     `ReplacementObjectLink`/`ReplacedObjectLink`.  Old objects are preserved unchanged.
//! 15. Auto-rotation of a `PublicKey` — follows `PrivateKeyLink`, graceful skip (RSA not yet supported).
//! 16. End-to-end cron: symmetric key is automatically rotated by the background cron thread.
//! 17. End-to-end cron: certificate auto-renewal creates new objects; old cert gains a
//!     `ReplacementObjectLink` pointing to the new cert.
//! 18. Production scenario: cert has only `rotate_interval` set (no explicit `rotate_date`).
//!     The cron must still auto-renew it using `initial_date`, which the `Certify` operation
//!     must set so that `is_due_for_rotation` can compute the first rotation deadline.
//! 19. New cert DER bytes differ from old cert DER bytes; old cert is preserved unchanged;
//!     `ReplacementObjectLink`/`ReplacedObjectLink` cross-links are correct.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::large_futures
)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::ObjectType,
        kmip_operations::{Certify, Export, GetAttributes, ReKey, SetAttribute},
        kmip_types::{
            CertificateAttributes, CryptographicAlgorithm, EncryptionKeyInformation, LinkType,
            UniqueIdentifier, WrappingMethod,
        },
        requests::{create_rsa_key_pair_request, symmetric_key_create_request},
    },
};
use cosmian_logger::log_init;

use crate::{
    config::ServerParams,
    core::{KMS, operations::run_auto_rotation},
    result::KResult,
    tests::test_utils::https_clap_config,
};

const USER: &str = "rotation_test_user@example.com";

/// Build a fresh KMS instance backed by an in-memory `SQLite` database.
async fn kms() -> Arc<KMS> {
    log_init(option_env!("RUST_LOG"));
    let clap_config = https_clap_config();
    Arc::new(
        KMS::instantiate(Arc::new(
            ServerParams::try_from(clap_config).expect("ServerParams"),
        ))
        .await
        .expect("KMS::instantiate"),
    )
}

// ─── helpers ─────────────────────────────────────────────────────────────────

async fn create_aes_256(kms: &Arc<KMS>) -> KResult<String> {
    let request = symmetric_key_create_request(
        kms.vendor_id(),
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        false,
        None,
    )?;
    Ok(kms
        .create(request, USER, None)
        .await?
        .unique_identifier
        .to_string())
}

async fn do_rekey(kms: &Arc<KMS>, uid: &str) -> KResult<(String, String)> {
    let resp = kms
        .rekey(
            ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                ..Default::default()
            },
            USER,
        )
        .await?;
    Ok((uid.to_owned(), resp.unique_identifier.to_string()))
}

async fn get_all_attrs(
    kms: &Arc<KMS>,
    uid: &str,
) -> KResult<
    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
> {
    Ok(kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                attribute_reference: None,
            },
            USER,
        )
        .await?
        .attributes)
}

/// Read attributes directly from the DB (bypasses `GetAttributes` filtering).
/// Use this helper to inspect rotation-specific fields (`rotate_generation`,
/// `rotate_interval`, etc.) that are stored as metadata but not mapped by
/// the KMIP `GetAttributes` operation.
async fn get_db_attrs(
    kms: &Arc<KMS>,
    uid: &str,
) -> KResult<
    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
> {
    Ok(kms
        .database
        .retrieve_object(uid)
        .await?
        .expect("object must exist in DB")
        .attributes()
        .to_owned())
}

async fn set_attr(
    kms: &Arc<KMS>,
    uid: &str,
    attribute: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute,
) -> KResult<()> {
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            new_attribute: attribute,
        },
        USER,
    )
    .await?;
    Ok(())
}

/// Export `data_uid` wrapped with `wrapping_uid` and store the blob under `dest_uid`.
async fn store_wrapped_copy(
    kms: &Arc<KMS>,
    data_uid: &str,
    wrapping_uid: &str,
    dest_uid: &str,
) -> KResult<()> {
    let resp = kms
        .export(
            Export {
                unique_identifier: Some(UniqueIdentifier::TextString(data_uid.to_owned())),
                key_format_type: None,
                key_wrap_type: Some(KeyWrapType::AsRegistered),
                key_compression_type: None,
                key_wrapping_specification: Some(KeyWrappingSpecification {
                    wrapping_method: WrappingMethod::Encrypt,
                    encryption_key_information: Some(EncryptionKeyInformation {
                        unique_identifier: UniqueIdentifier::TextString(wrapping_uid.to_owned()),
                        cryptographic_parameters: None,
                    }),
                    mac_or_signature_key_information: None,
                    attribute_name: None,
                    encoding_option: None,
                }),
            },
            USER,
        )
        .await?;
    let obj = resp.object;
    // Prefer embedded attributes; fall back to fetching the original key's DB attributes so
    // the stored copy always has CryptographicAlgorithm / length (needed by rekey).
    // Use the DB source (not GetAttributes) to avoid the `Raw` key_format_type normalization
    // that GetAttributes applies, which would break create_symmetric_key_and_tags.
    let mut attrs = match obj.attributes() {
        Ok(a) => a.clone(),
        Err(_) => get_db_attrs(kms, data_uid).await?,
    };
    // The stored copy must be Active so the rekey operation can discover it.
    attrs.state = Some(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::State::Active,
    );
    kms.database
        .create(
            Some(dest_uid.to_owned()),
            USER,
            &obj,
            &attrs,
            &std::collections::HashSet::new(),
        )
        .await?;
    Ok(())
}

// ─── tests ────────────────────────────────────────────────────────────────────

// 1. Basic rekey
#[tokio::test]
async fn test_rekey_produces_new_uid_and_material() -> KResult<()> {
    let kms = kms().await;
    let old_uid = create_aes_256(&kms).await?;
    let (_, new_uid) = do_rekey(&kms, &old_uid).await?;
    assert_ne!(old_uid, new_uid);
    let old_owm = kms
        .database
        .retrieve_object(&old_uid)
        .await?
        .expect("old key must still exist");
    let new_owm = kms
        .database
        .retrieve_object(&new_uid)
        .await?
        .expect("new key must exist");
    assert_ne!(
        old_owm.object().key_block()?.key_bytes()?,
        new_owm.object().key_block()?.key_bytes()?
    );
    Ok(())
}

// 2. KMIP Link chain
#[tokio::test]
async fn test_rekey_link_chain() -> KResult<()> {
    let kms = kms().await;
    let old_uid = create_aes_256(&kms).await?;
    let (_, new_uid) = do_rekey(&kms, &old_uid).await?;
    let old_attrs = get_all_attrs(&kms, &old_uid).await?;
    let new_attrs = get_all_attrs(&kms, &new_uid).await?;
    assert_eq!(
        old_attrs
            .get_link(LinkType::ReplacementObjectLink)
            .expect("must have ReplacementObjectLink")
            .to_string(),
        new_uid
    );
    assert_eq!(
        new_attrs
            .get_link(LinkType::ReplacedObjectLink)
            .expect("must have ReplacedObjectLink")
            .to_string(),
        old_uid
    );
    Ok(())
}

// 3. Rotation metadata
#[tokio::test]
async fn test_rekey_rotation_metadata() -> KResult<()> {
    let kms = kms().await;
    let uid0 = create_aes_256(&kms).await?;
    // time_normalize() truncates milliseconds; align `before` to the same granularity
    let before = time::OffsetDateTime::now_utc()
        .replace_millisecond(0)
        .expect("replace_millisecond(0)");
    let (_, uid1) = do_rekey(&kms, &uid0).await?;
    let attrs1 = get_db_attrs(&kms, &uid1).await?;
    assert_eq!(attrs1.rotate_generation, Some(1));
    let d1 = attrs1.rotate_date.expect("rotate_date must be set");
    assert!(d1 >= before, "d1={d1} must be >= before={before}");
    let (_, uid2) = do_rekey(&kms, &uid1).await?;
    let attrs2 = get_db_attrs(&kms, &uid2).await?;
    assert_eq!(attrs2.rotate_generation, Some(2));
    assert!(
        attrs2.rotate_date.expect("rotate_date must be set") >= d1,
        "second rotate_date must be >= first"
    );
    Ok(())
}

// 4. Rotation policy propagation on manual rekey:
// - old key gets rotate_interval = 0 (disabled)
// - new key does NOT inherit the policy (user must re-arm explicitly)
#[tokio::test]
async fn test_rekey_clears_old_and_does_not_propagate_policy() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(3600)).await?;
    set_attr(&kms, &uid, Attribute::RotateName("weekly".to_owned())).await?;
    set_attr(&kms, &uid, Attribute::RotateOffset(60)).await?;
    let (_, new_uid) = do_rekey(&kms, &uid).await?;

    // Old key: rotate_interval must be 0 so the cron does not pick it up again.
    // Use get_all_attrs (KMIP GetAttributes): after the fix to get_attributes.rs, rotation
    // policy fields are read from the metadata column, so this now returns the correct value.
    let old_attrs = get_all_attrs(&kms, &uid).await?;
    assert_eq!(
        old_attrs.rotate_interval,
        Some(0),
        "old key rotate_interval must be 0 after manual rekey"
    );

    // New key: manual rekey does NOT inherit the rotation policy.
    let new_attrs = get_db_attrs(&kms, &new_uid).await?;
    assert_eq!(
        new_attrs.rotate_interval,
        Some(0),
        "new key rotate_interval must be 0 after manual rekey (no auto-re-arm)"
    );
    assert_eq!(new_attrs.rotate_name, None);
    // rotate_offset is left as None on the new key (rekey.rs does not set it to Some(0))
    assert_eq!(new_attrs.rotate_offset, None);
    Ok(())
}

// 5. rotate_latest flag: new key gets true, old key gets false
#[tokio::test]
async fn test_rekey_rotate_latest_flag() -> KResult<()> {
    let kms = kms().await;
    let uid0 = create_aes_256(&kms).await?;
    let (_, uid1) = do_rekey(&kms, &uid0).await?;

    // After first rotation: uid1 is latest, uid0 is not.
    assert_eq!(get_db_attrs(&kms, &uid1).await?.rotate_latest, Some(true));
    assert_eq!(get_db_attrs(&kms, &uid0).await?.rotate_latest, Some(false));

    // After second rotation: uid2 is latest, uid1 is no longer.
    let (_, uid2) = do_rekey(&kms, &uid1).await?;
    assert_eq!(get_db_attrs(&kms, &uid2).await?.rotate_latest, Some(true));
    assert_eq!(get_db_attrs(&kms, &uid1).await?.rotate_latest, Some(false));
    // uid0 is unaffected (still false from the first rotation)
    assert_eq!(get_db_attrs(&kms, &uid0).await?.rotate_latest, Some(false));
    Ok(())
}

// 6. Rekey a wrapped key stays wrapped
#[tokio::test]
async fn test_rekey_wrapped_key_stays_wrapped() -> KResult<()> {
    let kms = kms().await;
    let wrapping_uid = create_aes_256(&kms).await?;
    let data_uid = create_aes_256(&kms).await?;
    let wrapped_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &data_uid, &wrapping_uid, &wrapped_uid).await?;
    let (_, new_uid) = do_rekey(&kms, &wrapped_uid).await?;
    assert!(
        kms.database
            .retrieve_object(&new_uid)
            .await?
            .expect("new key must exist")
            .object()
            .is_wrapped()
    );
    Ok(())
}

// 6. Rekey a wrapping key re-wraps dependants
#[tokio::test]
async fn test_rekey_wrapping_key_rewraps_dependants() -> KResult<()> {
    let kms = kms().await;
    let wrapping_uid = create_aes_256(&kms).await?;
    let data_uid = create_aes_256(&kms).await?;
    let wrapped_data_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &data_uid, &wrapping_uid, &wrapped_data_uid).await?;
    let (_, new_wrapping_uid) = do_rekey(&kms, &wrapping_uid).await?;
    let dep_attrs = get_all_attrs(&kms, &wrapped_data_uid).await?;
    assert_eq!(
        dep_attrs
            .get_link(LinkType::WrappingKeyLink)
            .expect("must have WrappingKeyLink")
            .to_string(),
        new_wrapping_uid
    );
    assert!(
        kms.database
            .retrieve_object(&wrapped_data_uid)
            .await?
            .expect("dep must still exist")
            .object()
            .is_wrapped()
    );
    Ok(())
}

// 7. Two successive rotations chain
#[tokio::test]
async fn test_rekey_two_successive_rotations() -> KResult<()> {
    let kms = kms().await;
    let uid0 = create_aes_256(&kms).await?;
    let (_, uid1) = do_rekey(&kms, &uid0).await?;
    let (_, uid2) = do_rekey(&kms, &uid1).await?;
    assert_ne!(uid0, uid1);
    assert_ne!(uid1, uid2);
    let attrs1 = get_all_attrs(&kms, &uid1).await?;
    assert_eq!(
        attrs1
            .get_link(LinkType::ReplacedObjectLink)
            .unwrap()
            .to_string(),
        uid0
    );
    assert_eq!(
        attrs1
            .get_link(LinkType::ReplacementObjectLink)
            .unwrap()
            .to_string(),
        uid2
    );
    let attrs2 = get_all_attrs(&kms, &uid2).await?;
    assert_eq!(
        attrs2
            .get_link(LinkType::ReplacedObjectLink)
            .unwrap()
            .to_string(),
        uid1
    );
    assert!(attrs2.get_link(LinkType::ReplacementObjectLink).is_none());
    assert_eq!(get_db_attrs(&kms, &uid1).await?.rotate_generation, Some(1));
    assert_eq!(get_db_attrs(&kms, &uid2).await?.rotate_generation, Some(2));
    Ok(())
}

// 8. Rekey non-existent key
#[tokio::test]
async fn test_rekey_unknown_uid_returns_error() -> KResult<()> {
    let kms = kms().await;
    do_rekey(&kms, "nonexistent-uid").await.unwrap_err();
    Ok(())
}

// 9. Auto-rotation: not yet due
#[tokio::test]
async fn test_auto_rotation_not_due_is_skipped() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(3600)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::InitialDate(time::OffsetDateTime::now_utc()),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_none()
    );
    Ok(())
}

// 10. Auto-rotation: interval=0 means disabled
#[tokio::test]
async fn test_auto_rotation_interval_zero_disabled() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(0)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(7200)),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_none()
    );
    Ok(())
}

// 11. Auto-rotation: past due
#[tokio::test]
async fn test_auto_rotation_past_due_is_rotated() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(60)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(120)),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_some()
    );
    Ok(())
}

// 12. Auto-rotation: exactly at boundary triggers rotation
#[tokio::test]
async fn test_auto_rotation_exactly_at_boundary() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(60)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(60)),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_some()
    );
    Ok(())
}

// 13. Auto-rotation: first-ever rotation triggered by InitialDate
#[tokio::test]
async fn test_auto_rotation_first_rotation_via_initial_date() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(100)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::InitialDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(200)),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_some()
    );
    Ok(())
}

// 14. Auto-rotation: multiple keys at once
#[tokio::test]
async fn test_auto_rotation_multiple_keys_in_one_pass() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid1 = create_aes_256(&kms).await?;
    let uid2 = create_aes_256(&kms).await?;
    for uid in [&uid1, &uid2] {
        set_attr(&kms, uid, Attribute::RotateInterval(60)).await?;
        set_attr(
            &kms,
            uid,
            Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(120)),
        )
        .await?;
    }
    run_auto_rotation(&kms).await;
    for uid in [&uid1, &uid2] {
        assert!(
            get_all_attrs(&kms, uid)
                .await?
                .get_link(LinkType::ReplacementObjectLink)
                .is_some(),
            "{uid} must be rotated"
        );
    }
    Ok(())
}

// 15. Auto-rotation: mixed due / not-due
#[tokio::test]
async fn test_auto_rotation_mixed_batch() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid_due = create_aes_256(&kms).await?;
    let uid_not_due = create_aes_256(&kms).await?;
    set_attr(&kms, &uid_due, Attribute::RotateInterval(60)).await?;
    set_attr(
        &kms,
        &uid_due,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(120)),
    )
    .await?;
    set_attr(&kms, &uid_not_due, Attribute::RotateInterval(3600)).await?;
    set_attr(
        &kms,
        &uid_not_due,
        Attribute::InitialDate(time::OffsetDateTime::now_utc()),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid_due)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_some()
    );
    assert!(
        get_all_attrs(&kms, &uid_not_due)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_none()
    );
    Ok(())
}

// 16. Disable rotation after enabling it
#[tokio::test]
async fn test_disable_rotation_after_enabling() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(3600)).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(0)).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(7200)),
    )
    .await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_none()
    );
    Ok(())
}

// 17. Key without interval is never auto-rotated
#[tokio::test]
async fn test_key_without_interval_never_auto_rotated() -> KResult<()> {
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    run_auto_rotation(&kms).await;
    assert!(
        get_all_attrs(&kms, &uid)
            .await?
            .get_link(LinkType::ReplacementObjectLink)
            .is_none()
    );
    Ok(())
}

// 17b. Auto-rotation policy transfer: old key gets interval=0, new key inherits interval.
#[tokio::test]
async fn test_auto_rotation_transfers_policy_to_new_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(3600)).await?;
    set_attr(&kms, &uid, Attribute::RotateName("hourly".to_owned())).await?;
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(7200)),
    )
    .await?;

    run_auto_rotation(&kms).await;

    // Use get_all_attrs (KMIP GetAttributes) for both checks — after the fix to
    // get_attributes.rs, rotation policy fields are always read from the metadata
    // column (not the key block), so GetAttributes now returns the correct values.
    let old_attrs = get_all_attrs(&kms, &uid).await?;
    let new_uid = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old key must have ReplacementObjectLink after auto-rotation")
        .to_string();

    assert_eq!(
        old_attrs.rotate_interval,
        Some(0),
        "old key rotate_interval must be 0 after auto-rotation"
    );

    // New key: must inherit the rotation policy.
    let new_attrs = get_db_attrs(&kms, &new_uid).await?;
    assert_eq!(
        new_attrs.rotate_interval,
        Some(3600),
        "new key must inherit rotate_interval from the old key"
    );
    assert_eq!(
        new_attrs.rotate_name.as_deref(),
        Some("hourly"),
        "new key must inherit rotate_name from the old key"
    );
    Ok(())
}

// ─── RSA key pair + self-signed certificate helper ───────────────────────────

/// Create an RSA-2048 key pair and self-sign the public key as a certificate.
///
/// Returns `(private_key_uid, public_key_uid, cert_uid)`.
async fn create_rsa_key_pair_and_cert(kms: &Arc<KMS>) -> KResult<(String, String, String)> {
    let kp_req = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        Vec::<String>::new(),
        2048,
        false,
        None,
    )?;
    let kp_resp = kms.create_key_pair(kp_req, USER, None).await?;
    let private_key_uid = kp_resp.private_key_unique_identifier.to_string();
    let public_key_uid = kp_resp.public_key_unique_identifier.to_string();

    // Self-sign: certify the public key without specifying an issuer in the request.
    // The certify path reads PrivateKeyLink from the stored public key attributes to find
    // the signing key — passing it in the request attributes would trigger the non-self-signed
    // path, which requires an existing issuer certificate.
    let certify_attrs = Attributes {
        object_type: Some(ObjectType::Certificate),
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(
            "CN=AutoRotateTest",
        )?),
        ..Attributes::default()
    };
    let cert_resp = kms
        .certify(
            Certify {
                unique_identifier: Some(UniqueIdentifier::TextString(public_key_uid.clone())),
                attributes: Some(certify_attrs),
                ..Certify::default()
            },
            USER,
            None,
        )
        .await?;
    let cert_uid = cert_resp.unique_identifier.to_string();

    Ok((private_key_uid, public_key_uid, cert_uid))
}

// 18. Re-keyed key carries a `ReplacedObjectLink` KMIP attribute pointing to the old key ID.
//
// This is the canonical proof that the KMIP link set by `rekey` is readable back through
// `GetAttributes` and that it contains exactly the original key UID — independent of the
// broader link-chain test above.
#[tokio::test]
async fn test_rekeyed_key_has_replaced_object_link_to_old_key() -> KResult<()> {
    let kms = kms().await;

    // Create the original key.
    let old_uid = create_aes_256(&kms).await?;

    // Rotate it.
    let (_, new_uid) = do_rekey(&kms, &old_uid).await?;

    // Verify: the *new* key must carry a `ReplacedObjectLink` pointing to the *old* key.
    let new_attrs = get_all_attrs(&kms, &new_uid).await?;
    let replaced_link = new_attrs
        .get_link(LinkType::ReplacedObjectLink)
        .expect("new key must carry a ReplacedObjectLink KMIP attribute after rotation");
    assert_eq!(
        replaced_link.to_string(),
        old_uid,
        "ReplacedObjectLink on the new key must equal the old key UID"
    );

    // Cross-check: the *old* key must carry a `ReplacementObjectLink` pointing to the *new* key.
    let old_attrs = get_all_attrs(&kms, &old_uid).await?;
    let replacement_link = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old key must carry a ReplacementObjectLink KMIP attribute after rotation");
    assert_eq!(
        replacement_link.to_string(),
        new_uid,
        "ReplacementObjectLink on the old key must equal the new key UID"
    );

    Ok(())
}

// 19. Auto-rotation of a Certificate: creates a new cert + key pair, links old → new.
#[tokio::test]
async fn test_auto_rotation_certificate() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;

    let (_, _, cert_uid) = create_rsa_key_pair_and_cert(&kms).await?;

    // Mark the certificate as overdue for rotation.
    set_attr(&kms, &cert_uid, Attribute::RotateInterval(60)).await?;
    set_attr(
        &kms,
        &cert_uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(120)),
    )
    .await?;

    let gen_before = get_db_attrs(&kms, &cert_uid)
        .await?
        .rotate_generation
        .unwrap_or(0);

    run_auto_rotation(&kms).await;

    // Old cert must have a ReplacementObjectLink pointing to the new cert.
    let old_attrs = get_db_attrs(&kms, &cert_uid).await?;
    let new_cert_uid = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old cert must carry ReplacementObjectLink after auto-renewal")
        .to_string();

    // New cert must have incremented rotate_generation.
    let new_attrs = get_db_attrs(&kms, &new_cert_uid).await?;
    assert_eq!(
        new_attrs.rotate_generation,
        Some(gen_before + 1),
        "new certificate rotate_generation must be gen_before+1 after auto-renewal"
    );

    // Old cert's rotation policy must be disabled (interval = 0).
    assert_eq!(
        old_attrs.rotate_interval,
        Some(0),
        "old cert rotate_interval must be 0 after renewal so it is not picked up again"
    );

    // New cert must have inherited the rotation policy from the old cert.
    assert_eq!(
        new_attrs.rotate_interval,
        Some(60),
        "new cert must inherit rotate_interval from the old cert"
    );

    Ok(())
}

// 20. Auto-rotation: PublicKey arm triggers a full asymmetric key pair rotation.
//     When the rotation policy is set only on the PUBLIC key, `run_auto_rotation` must:
//     - create a brand-new private + public key pair,
//     - set `ReplacementObjectLink` on BOTH old keys,
//     - clear `rotate_interval = 0` on BOTH old keys,
//     - transfer the rotation policy to the NEW private key.
#[tokio::test]
async fn test_auto_rotation_public_key_triggers_full_rsa_keypair_rotation() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::State, kmip_2_1::kmip_attributes::Attribute,
    };
    let kms = kms().await;

    let (private_key_uid, public_key_uid, _) = create_rsa_key_pair_and_cert(&kms).await?;

    // Set rotation policy ONLY on the public key — the private key has no policy.
    // This simulates a user who accidentally or intentionally set the policy on the public key.
    set_attr(&kms, &public_key_uid, Attribute::RotateInterval(60)).await?;
    set_attr(
        &kms,
        &public_key_uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(120)),
    )
    .await?;

    // Run auto-rotation — this must NOT panic and must NOT emit an error warning.
    run_auto_rotation(&kms).await;

    // Old PRIVATE key must now have a ReplacementObjectLink (the full pair was rotated).
    let old_private_attrs = get_db_attrs(&kms, &private_key_uid).await?;
    let new_private_uid = old_private_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old private key must have ReplacementObjectLink after pair rotation")
        .to_string();

    // Old PRIVATE key must have rotate_interval = 0 (disabled).
    assert_eq!(
        old_private_attrs.rotate_interval,
        Some(0),
        "old private key rotate_interval must be 0 after rotation"
    );

    // Old PUBLIC key must now have a ReplacementObjectLink.
    let old_public_attrs = get_db_attrs(&kms, &public_key_uid).await?;
    let _new_public_uid = old_public_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old public key must have ReplacementObjectLink after pair rotation")
        .to_string();

    // Old PUBLIC key must have rotate_interval = 0 (disabled).
    assert_eq!(
        old_public_attrs.rotate_interval,
        Some(0),
        "old public key rotate_interval must be 0 after rotation"
    );

    // NEW private key must have inherited the rotation policy (interval = 60 s).
    let new_private_attrs = get_db_attrs(&kms, &new_private_uid).await?;
    assert_eq!(
        new_private_attrs.rotate_interval,
        Some(60),
        "new private key must inherit rotate_interval from old public key policy"
    );

    // NEW keys must be Active (not PreActive) — they replace an Active key pair.
    assert_eq!(
        new_private_attrs.state,
        Some(State::Active),
        "new private key must be Active after rotation"
    );
    let new_public_uid = old_public_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old public key must have ReplacementObjectLink")
        .to_string();
    let new_public_attrs = get_db_attrs(&kms, &new_public_uid).await?;
    assert_eq!(
        new_public_attrs.state,
        Some(State::Active),
        "new public key must be Active after rotation"
    );

    Ok(())
}

// 21. End-to-end cron: symmetric key created with a 2-second rotation interval is automatically
//     rotated by the background cron thread without any explicit `run_auto_rotation` call.
//
// The test verifies that:
//   - after waiting ~6 s (≥ 2 cron ticks at 2 s interval), the original key carries a
//     `ReplacementObjectLink` attribute.
//   - `rotate_generation` on the original key is 0 (it was never manually rekeyed),
//     and on the replacement it is 1.
#[tokio::test]
async fn test_cron_automatically_rotates_symmetric_key() -> KResult<()> {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;

    use crate::cron::spawn_auto_rotation_cron;

    // Build a KMS with a 2-second auto-rotation check interval so the cron fires quickly.
    log_init(option_env!("RUST_LOG"));
    let mut clap_config = https_clap_config();
    clap_config.auto_rotation_check_interval_secs = 2;
    let kms = Arc::new(
        KMS::instantiate(Arc::new(
            ServerParams::try_from(clap_config).expect("ServerParams"),
        ))
        .await
        .expect("KMS::instantiate"),
    );

    // Create an AES-256 key and mark it as already overdue (rotate_date = 10 s in the past).
    let uid = create_aes_256(&kms).await?;
    set_attr(&kms, &uid, Attribute::RotateInterval(1)).await?; // interval = 1 s → always due
    set_attr(
        &kms,
        &uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(10)),
    )
    .await?;

    // Spawn the auto-rotation cron thread.
    let shutdown_tx = spawn_auto_rotation_cron(kms.clone());

    // Wait long enough for at least two cron ticks (2 × 2 s + 2 s margin).
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    // Stop the cron thread.
    let _ = shutdown_tx.send(());

    // The original key must now have a ReplacementObjectLink (= rotation occurred).
    let attrs = get_all_attrs(&kms, &uid).await?;
    let replacement_uid = attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("cron must have rotated the symmetric key: ReplacementObjectLink is missing")
        .to_string();

    // The replacement key must have rotate_generation = 1.
    let new_attrs = get_db_attrs(&kms, &replacement_uid).await?;
    assert_eq!(
        new_attrs.rotate_generation,
        Some(1),
        "replacement key must have rotate_generation = 1"
    );

    Ok(())
}

// 22. End-to-end cron: certificate created with a 2-second rotation interval is automatically
//     renewed by the background cron thread without any explicit `run_auto_rotation` call.
//
// Certificate auto-rotation creates new objects (new key pair + new certificate) and links
// the old cert to the new one via ReplacementObjectLink.  The test verifies:
//   - the old cert gains a ReplacementObjectLink after at least one cron tick.
//   - the replacement certificate has rotate_generation >= 1.
#[tokio::test]
async fn test_cron_automatically_renews_certificate() -> KResult<()> {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;

    use crate::cron::spawn_auto_rotation_cron;

    log_init(option_env!("RUST_LOG"));
    let mut clap_config = https_clap_config();
    clap_config.auto_rotation_check_interval_secs = 2;
    let kms = Arc::new(
        KMS::instantiate(Arc::new(
            ServerParams::try_from(clap_config).expect("ServerParams"),
        ))
        .await
        .expect("KMS::instantiate"),
    );

    // Create an RSA key pair and self-sign a certificate.
    let (_private_key_uid, _public_key_uid, cert_uid) = create_rsa_key_pair_and_cert(&kms).await?;

    // Mark the certificate as overdue for rotation (interval = 1 s, last rotate_date = 10 s ago).
    set_attr(&kms, &cert_uid, Attribute::RotateInterval(1)).await?;
    set_attr(
        &kms,
        &cert_uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(10)),
    )
    .await?;

    // Spawn the auto-rotation cron thread.
    let shutdown_tx = spawn_auto_rotation_cron(kms.clone());

    // Wait long enough for at least two cron ticks (2 × 2 s + 2 s margin).
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    // Stop the cron thread.
    let _ = shutdown_tx.send(());

    // The old cert must now have a ReplacementObjectLink (= at least one renewal occurred).
    let old_attrs = get_db_attrs(&kms, &cert_uid).await?;
    let new_cert_uid = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect(
            "cron must have renewed the certificate: \
             ReplacementObjectLink is missing on old cert",
        )
        .to_string();

    // The replacement certificate must have rotate_generation >= 1.
    let new_attrs = get_db_attrs(&kms, &new_cert_uid).await?;
    assert!(
        new_attrs.rotate_generation.unwrap_or(0) >= 1,
        "replacement certificate must have rotate_generation >= 1 \
         (got {:?})",
        new_attrs.rotate_generation
    );

    Ok(())
}

// 23. Production scenario: a certificate is created with only rotate_interval set (no explicit
//     rotate_date).  The `Certify` operation must stamp initial_date on the certificate so
//     that `is_due_for_rotation` can compute the first rotation deadline without the user
//     needing to call SetAttribute(RotateDate) beforehand.
//
// Without initial_date being set, is_due_for_rotation returns false for every cron tick no
// matter how large the interval, and the user sees "Running scheduled key auto-rotation check"
// in the logs with no certificate ever renewed.
#[tokio::test]
async fn test_cron_renews_cert_with_only_rotate_interval_set() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;

    use crate::cron::spawn_auto_rotation_cron;

    log_init(option_env!("RUST_LOG"));
    let mut clap_config = https_clap_config();
    clap_config.auto_rotation_check_interval_secs = 2;
    let kms = Arc::new(
        KMS::instantiate(Arc::new(
            ServerParams::try_from(clap_config).expect("ServerParams"),
        ))
        .await
        .expect("KMS::instantiate"),
    );

    // Create the cert and set ONLY rotate_interval — no rotate_date, no rotate_offset.
    // This is the typical production flow where the user configures a rotation policy
    // at creation time without providing a starting date.
    let (_private_key_uid, _public_key_uid, cert_uid) = create_rsa_key_pair_and_cert(&kms).await?;
    set_attr(&kms, &cert_uid, Attribute::RotateInterval(1)).await?;
    // Deliberately do NOT call set_attr(RotateDate). The cert relies entirely on
    // initial_date (set by Certify) for the first-rotation-deadline computation.

    // Confirm initial_date was stamped by Certify.
    let attrs_created = get_db_attrs(&kms, &cert_uid).await?;
    assert!(
        attrs_created.initial_date.is_some(),
        "Certify must set initial_date on the certificate so that \
         is_due_for_rotation works without an explicit rotate_date"
    );

    // Spawn the auto-rotation cron and wait long enough for it to fire.
    let shutdown_tx = spawn_auto_rotation_cron(kms.clone());
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
    let _ = shutdown_tx.send(());

    // The old cert must have a ReplacementObjectLink (= renewal occurred).
    let old_attrs = get_db_attrs(&kms, &cert_uid).await?;
    let new_cert_uid = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect(
            "old cert must carry ReplacementObjectLink even without an explicit rotate_date \
             — initial_date must have been used to trigger the first renewal",
        )
        .to_string();

    // New cert must have rotate_generation >= 1.
    let new_attrs = get_db_attrs(&kms, &new_cert_uid).await?;
    assert!(
        new_attrs.rotate_generation.unwrap_or(0) >= 1,
        "replacement certificate rotate_generation must be >= 1 (got {:?})",
        new_attrs.rotate_generation
    );

    Ok(())
}

// 25. After auto-rotation the new certificate has different DER bytes and a fresh validity.
//
// The test verifies the "create new objects" renewal semantics:
//   1. The old cert's DER bytes are UNCHANGED after rotation (it is not overwritten).
//   2. The old cert gains a ReplacementObjectLink → new cert UID.
//   3. The new cert's DER bytes differ from the old cert's DER bytes.
//   4. The new cert's NotAfter is at or after the old cert's NotAfter (fresh validity).
//   5. The new cert carries rotate_generation = gen_before + 1.
//   6. The old cert's rotation policy (rotate_interval) is cleared.
//   7. The new cert carries a ReplacedObjectLink → old cert UID.
#[tokio::test]
async fn test_cert_auto_rotation_updates_der_bytes() -> KResult<()> {
    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::kmip_2_1::{kmip_attributes::Attribute, kmip_objects::Object},
        cosmian_kms_crypto::openssl::kmip_certificate_to_openssl,
    };

    log_init(option_env!("RUST_LOG"));
    let kms = kms().await;

    let (_, _, cert_uid) = create_rsa_key_pair_and_cert(&kms).await?;

    // Mark the cert as overdue so run_auto_rotation picks it up immediately.
    set_attr(&kms, &cert_uid, Attribute::RotateInterval(1)).await?;
    set_attr(
        &kms,
        &cert_uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(10)),
    )
    .await?;

    // Capture the DER bytes and NotAfter of the OLD cert BEFORE rotation.
    let (der_before, not_after_before) = {
        let owm = kms
            .database
            .retrieve_object(&cert_uid)
            .await?
            .expect("cert must exist");
        let x509 = kmip_certificate_to_openssl(owm.object())?;
        let not_after = x509.not_after().to_string();
        let der = match owm.object() {
            Object::Certificate(c) => c.certificate_value.clone(),
            other => panic!("expected Certificate, got {other:?}"),
        };
        (der, not_after)
    };
    let gen_before = get_db_attrs(&kms, &cert_uid)
        .await?
        .rotate_generation
        .unwrap_or(0);

    // Wait 1 second so the new NotAfter (computed as `now + 365 days`) is guaranteed to
    // be strictly at or after the old NotAfter.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Trigger a single auto-rotation pass.
    run_auto_rotation(&kms).await;

    // 1. Old cert DER bytes must be UNCHANGED (cert is preserved, not overwritten).
    let old_owm_after = kms
        .database
        .retrieve_object(&cert_uid)
        .await?
        .expect("old cert must still exist");
    let der_old_after = match old_owm_after.object() {
        Object::Certificate(c) => c.certificate_value.clone(),
        other => panic!("expected Certificate, got {other:?}"),
    };
    assert_eq!(
        der_before, der_old_after,
        "old cert DER bytes must be UNCHANGED after renewal (it is not overwritten)"
    );

    // 2. Old cert must have a ReplacementObjectLink.
    let old_attrs_after = get_db_attrs(&kms, &cert_uid).await?;
    let new_cert_uid = old_attrs_after
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old cert must carry ReplacementObjectLink after auto-renewal")
        .to_string();

    // 3. New cert DER bytes must differ from old cert DER bytes.
    let new_owm = kms
        .database
        .retrieve_object(&new_cert_uid)
        .await?
        .expect("new cert must exist");
    let x509_new = kmip_certificate_to_openssl(new_owm.object())?;
    let not_after_new = x509_new.not_after().to_string();
    let der_new = match new_owm.object() {
        Object::Certificate(c) => c.certificate_value.clone(),
        other => panic!("expected Certificate, got {other:?}"),
    };
    assert_ne!(
        der_before, der_new,
        "new cert DER bytes must differ from old cert DER bytes"
    );

    // 4. New cert NotAfter must be at or after the old cert's NotAfter (fresh validity window).
    assert!(
        not_after_new >= not_after_before,
        "new cert NotAfter must be >= old cert NotAfter: \
         renewal must issue a fresh cert (before={not_after_before}, new={not_after_new})"
    );

    // 5. New cert rotate_generation = gen_before + 1.
    let new_attrs = get_db_attrs(&kms, &new_cert_uid).await?;
    assert_eq!(
        new_attrs.rotate_generation,
        Some(gen_before + 1),
        "new cert rotate_generation must be gen_before+1 after auto-renewal"
    );

    // 6. Old cert rotation policy must be disabled (interval = 0).
    assert_eq!(
        old_attrs_after.rotate_interval,
        Some(0),
        "old cert rotate_interval must be 0 after renewal"
    );

    // 7. New cert must carry ReplacedObjectLink → old cert.
    let replaced_link = new_attrs
        .get_link(LinkType::ReplacedObjectLink)
        .expect("new cert must carry ReplacedObjectLink after auto-renewal");
    assert_eq!(
        replaced_link.to_string(),
        cert_uid,
        "new cert ReplacedObjectLink must point to the old cert UID"
    );

    Ok(())
}

// ─── Wrapped-key rotation tests ───────────────────────────────────────────────
//
// These tests exercise the two server-side fixes introduced for wrapped-key
// rotation support:
//
//  a) `set_attribute.rs`: `SetAttribute(RotateInterval)` no longer fails when
//     the target key is stored as a ByteString (i.e. it is wrapped/encrypted).
//     For wrapped keys the attribute is persisted in the metadata column.
//
//  b) `rekey.rs`: after rotating a wrapped symmetric key the new key carries a
//     `WrappingKeyLink` pointing to the same wrapping key as the original.

// 26. SetAttribute(RotateInterval) does not error on a wrapped symmetric key.
//
// Before the fix, `SetAttribute` on a wrapped key would call `attributes_mut()`
// on a ByteString key block and propagate the resulting error.  After the fix
// the object-embedded attributes update is silently skipped and the attribute
// is stored only via `update_object` (metadata column).
#[tokio::test]
async fn test_set_attribute_works_on_wrapped_symmetric_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;

    let wrapping_uid = create_aes_256(&kms).await?;
    let data_uid = create_aes_256(&kms).await?;
    let wrapped_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &data_uid, &wrapping_uid, &wrapped_uid).await?;

    // This must not return an error even though the key is wrapped.
    set_attr(&kms, &wrapped_uid, Attribute::RotateInterval(3600)).await?;

    // The attribute must be readable from the metadata column via get_attributes.
    let attrs = get_all_attrs(&kms, &wrapped_uid).await?;
    assert_eq!(
        attrs.rotate_interval,
        Some(3600),
        "rotate_interval must be persisted and readable after SetAttribute on a wrapped key"
    );

    Ok(())
}

// 27. After rekey of a wrapped symmetric key the new key carries a WrappingKeyLink.
//
// Before the fix, `rekey.rs` built the new key's attributes from the unwrapped
// key material — which has no wrapping data — so the `WrappingKeyLink` was never
// set on the new key.  After the fix the wrapping key UID is captured before
// unwrapping and explicitly written into `new_key_attrs`.
#[tokio::test]
async fn test_rekey_wrapped_sym_key_preserves_wrapping_key_link() -> KResult<()> {
    let kms = kms().await;

    let wrapping_uid = create_aes_256(&kms).await?;
    let data_uid = create_aes_256(&kms).await?;
    let wrapped_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &data_uid, &wrapping_uid, &wrapped_uid).await?;

    // Rotate the wrapped key.
    let (_, new_uid) = do_rekey(&kms, &wrapped_uid).await?;

    // The new key must still be wrapped.
    assert!(
        kms.database
            .retrieve_object(&new_uid)
            .await?
            .expect("new key must exist")
            .object()
            .is_wrapped(),
        "new key after rotating a wrapped key must itself be wrapped"
    );

    // The new key must have a WrappingKeyLink pointing to the original wrapping key.
    let new_attrs = get_all_attrs(&kms, &new_uid).await?;
    let wrapping_link = new_attrs
        .get_link(LinkType::WrappingKeyLink)
        .expect("new wrapped key must carry a WrappingKeyLink after rotation");
    assert_eq!(
        wrapping_link.to_string(),
        wrapping_uid,
        "WrappingKeyLink on the new key must point to the same wrapping key as the original"
    );

    Ok(())
}

// 28. Auto-rotation of a wrapped symmetric key: new key is wrapped with same wrapping key.
//
// Full end-to-end test: set a rotation policy on a wrapped key, back-date the rotation
// due date so it fires immediately, call `run_auto_rotation`, and verify:
//   - the original wrapped key gains a `ReplacementObjectLink`.
//   - the replacement is also wrapped (ByteString key block).
//   - the replacement carries a `WrappingKeyLink` to the same wrapping key.
//   - the rotation policy (interval, name) is transferred to the new key.
#[tokio::test]
async fn test_auto_rotation_wrapped_sym_key_end_to_end() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;

    let wrapping_uid = create_aes_256(&kms).await?;
    let data_uid = create_aes_256(&kms).await?;
    let wrapped_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &data_uid, &wrapping_uid, &wrapped_uid).await?;

    // Arm the rotation policy on the wrapped key.
    set_attr(&kms, &wrapped_uid, Attribute::RotateInterval(3600)).await?;
    set_attr(
        &kms,
        &wrapped_uid,
        Attribute::RotateName("hourly".to_owned()),
    )
    .await?;
    // Back-date the rotate_date so the key is immediately due.
    set_attr(
        &kms,
        &wrapped_uid,
        Attribute::RotateDate(time::OffsetDateTime::now_utc() - time::Duration::seconds(7200)),
    )
    .await?;

    // Trigger a single auto-rotation pass.
    run_auto_rotation(&kms).await;

    // Original key must have a ReplacementObjectLink.
    let orig_attrs = get_all_attrs(&kms, &wrapped_uid).await?;
    let new_uid = orig_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("original wrapped key must have ReplacementObjectLink after auto-rotation")
        .to_string();

    // Replacement must be wrapped.
    assert!(
        kms.database
            .retrieve_object(&new_uid)
            .await?
            .expect("replacement must exist")
            .object()
            .is_wrapped(),
        "replacement key after auto-rotating a wrapped key must itself be wrapped"
    );

    // Replacement must carry a WrappingKeyLink → original wrapping key.
    let new_attrs = get_all_attrs(&kms, &new_uid).await?;
    let wrapping_link = new_attrs
        .get_link(LinkType::WrappingKeyLink)
        .expect("replacement wrapped key must carry a WrappingKeyLink");
    assert_eq!(
        wrapping_link.to_string(),
        wrapping_uid,
        "WrappingKeyLink on the replacement must point to the original wrapping key"
    );

    // Rotation policy must be transferred to the new key.
    let new_db_attrs = get_db_attrs(&kms, &new_uid).await?;
    assert_eq!(
        new_db_attrs.rotate_interval,
        Some(3600),
        "replacement key must inherit rotate_interval"
    );
    assert_eq!(
        new_db_attrs.rotate_name.as_deref(),
        Some("hourly"),
        "replacement key must inherit rotate_name"
    );

    Ok(())
}

// 29. SetAttribute(RotateInterval) does not error on a wrapped RSA private key.
//
// The `set_attribute.rs` fix applies generically to any wrapped object, not just
// symmetric keys.  This test verifies the same behaviour for a plain RSA private
// key.  (Auto-rotation of RSA wrapped private keys is a separate, not-yet-
// implemented feature; this test only covers the `SetAttribute` path.)
#[tokio::test]
async fn test_set_attribute_works_on_wrapped_rsa_private_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attribute;
    let kms = kms().await;

    let (private_key_uid, _, _) = create_rsa_key_pair_and_cert(&kms).await?;

    // Wrap the private key with an AES wrapping key.
    let wrapping_uid = create_aes_256(&kms).await?;
    let wrapped_private_uid = uuid::Uuid::new_v4().to_string();
    store_wrapped_copy(&kms, &private_key_uid, &wrapping_uid, &wrapped_private_uid).await?;

    // SetAttribute must not fail on the wrapped private key.
    set_attr(&kms, &wrapped_private_uid, Attribute::RotateInterval(86400)).await?;

    // The attribute must be readable from the metadata column.
    let attrs = get_all_attrs(&kms, &wrapped_private_uid).await?;
    assert_eq!(
        attrs.rotate_interval,
        Some(86400),
        "rotate_interval must be persisted and readable after SetAttribute \
         on a wrapped RSA private key"
    );

    Ok(())
}

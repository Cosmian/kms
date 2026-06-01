//! Integration tests for the auto-rotation scheduler.
//!
//! These tests verify that `auto_rotate_key` correctly delegates to the
//! existing rekey pipeline (`rekey`, `rekey_keypair`, `recertify`) and
//! properly transfers the rotation policy to the new key.

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_types::{CryptographicAlgorithm, LinkType, RecommendedCurve},
    requests::{create_ec_key_pair_request, symmetric_key_create_request},
};
use time::OffsetDateTime;

use crate::{
    config::ServerParams,
    core::{KMS, operations::auto_rotate_key},
    result::KResult,
    tests::test_utils::https_clap_config,
};

const OWNER: &str = "auto_rotate_test_user";
const EMPTY_TAGS: [&str; 0] = [];

/// Helper: create a test KMS instance.
async fn test_kms() -> KResult<Arc<KMS>> {
    let clap_config = https_clap_config();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?,
    ))
}

/// Helper: set rotation policy on an object.
async fn set_rotation_policy(kms: &KMS, uid: &str, interval_secs: i64) -> KResult<()> {
    if let Some(owm) = kms.database.retrieve_object(uid).await? {
        let mut attrs = owm.attributes().clone();
        attrs.rotate_interval = Some(interval_secs);
        // Set initial_date far in the past so the key appears "due" for rotation.
        attrs.initial_date =
            Some(OffsetDateTime::now_utc() - time::Duration::seconds(interval_secs + 60));
        let tags = kms.database.retrieve_tags(uid).await?;
        kms.database
            .update_object(uid, owm.object(), &attrs, Some(&tags))
            .await?;
    }
    Ok(())
}

/// Helper: create an active AES-256 key, return its UID.
async fn create_active_aes_key(kms: &KMS) -> KResult<String> {
    // symmetric_key_create_request already sets activation_date = now → key is Active
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let response = kms.create(request, OWNER).await?;
    Ok(response.unique_identifier.to_string())
}

/// Helper: create an active EC P-256 key pair, return `(sk_uid, pk_uid)`.
async fn create_active_ec_keypair(kms: &KMS) -> KResult<(String, String)> {
    let request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let response = kms.create_key_pair(request, OWNER).await?;
    let sk_uid = response.private_key_unique_identifier.to_string();
    let pk_uid = response.public_key_unique_identifier.to_string();
    Ok((sk_uid, pk_uid))
}

// ─── Symmetric Key Tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_auto_rotate_symmetric_key() -> KResult<()> {
    let kms = test_kms().await?;
    let key_uid = create_active_aes_key(&kms).await?;

    // Set rotation policy.
    set_rotation_policy(&kms, &key_uid, 3600).await?;

    // Trigger auto-rotation.
    auto_rotate_key(&kms, &key_uid, OWNER).await?;

    // Verify old key has rotate_interval = 0.
    let old_owm = kms.database.retrieve_object(&key_uid).await?.unwrap();
    assert_eq!(old_owm.attributes().rotate_interval, Some(0));

    // Verify old key has a ReplacementObjectLink.
    let replacement_link = old_owm
        .attributes()
        .get_link(LinkType::ReplacementObjectLink);
    assert!(
        replacement_link.is_some(),
        "old key should have ReplacementObjectLink"
    );
    let new_uid = replacement_link.unwrap().to_string();

    // Verify new key has rotation policy transferred.
    let new_owm = kms.database.retrieve_object(&new_uid).await?.unwrap();
    assert_eq!(new_owm.attributes().rotate_interval, Some(3600));
    assert!(new_owm.attributes().initial_date.is_some());

    // Verify new key has ReplacedObjectLink pointing to old key.
    let replaced_link = new_owm.attributes().get_link(LinkType::ReplacedObjectLink);
    assert!(replaced_link.is_some());
    assert_eq!(replaced_link.unwrap().to_string(), key_uid);

    Ok(())
}

#[tokio::test]
async fn test_auto_rotate_symmetric_key_skips_zero_interval() -> KResult<()> {
    let kms = test_kms().await?;
    let key_uid = create_active_aes_key(&kms).await?;

    // Set rotate_interval = 0 (disabled).
    if let Some(owm) = kms.database.retrieve_object(&key_uid).await? {
        let mut attrs = owm.attributes().clone();
        attrs.rotate_interval = Some(0);
        let tags = kms.database.retrieve_tags(&key_uid).await?;
        kms.database
            .update_object(&key_uid, owm.object(), &attrs, Some(&tags))
            .await?;
    }

    // Trigger auto-rotation — should be a no-op.
    auto_rotate_key(&kms, &key_uid, OWNER).await?;

    // Verify key has NO ReplacementObjectLink (was not rotated).
    let owm = kms.database.retrieve_object(&key_uid).await?.unwrap();
    assert!(
        owm.attributes()
            .get_link(LinkType::ReplacementObjectLink)
            .is_none(),
        "key with rotate_interval=0 should not be rotated"
    );

    Ok(())
}

#[tokio::test]
async fn test_auto_rotate_symmetric_key_double_chain() -> KResult<()> {
    let kms = test_kms().await?;
    let key_a = create_active_aes_key(&kms).await?;

    // Set rotation policy on key A.
    set_rotation_policy(&kms, &key_a, 3600).await?;

    // First rotation: A → B.
    auto_rotate_key(&kms, &key_a, OWNER).await?;
    let owm_a = kms.database.retrieve_object(&key_a).await?.unwrap();
    let key_b = owm_a
        .attributes()
        .get_link(LinkType::ReplacementObjectLink)
        .unwrap()
        .to_string();

    // Second rotation: B → C (policy was transferred to B).
    auto_rotate_key(&kms, &key_b, OWNER).await?;
    let owm_b = kms.database.retrieve_object(&key_b).await?.unwrap();
    let key_c = owm_b
        .attributes()
        .get_link(LinkType::ReplacementObjectLink)
        .unwrap()
        .to_string();

    // Verify chain: A → B → C.
    assert_ne!(key_a, key_b);
    assert_ne!(key_b, key_c);
    assert_ne!(key_a, key_c);

    // Verify C has rotation policy.
    let owm_c = kms.database.retrieve_object(&key_c).await?.unwrap();
    assert_eq!(owm_c.attributes().rotate_interval, Some(3600));

    // Verify B has rotate_interval = 0 (cleared by second rotation).
    assert_eq!(owm_b.attributes().rotate_interval, Some(0));

    Ok(())
}

// ─── EC Key Pair Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_auto_rotate_ec_keypair() -> KResult<()> {
    let kms = test_kms().await?;
    let (sk_uid, _pk_uid) = create_active_ec_keypair(&kms).await?;

    // Set rotation policy on private key.
    set_rotation_policy(&kms, &sk_uid, 7200).await?;

    // Trigger auto-rotation.
    auto_rotate_key(&kms, &sk_uid, OWNER).await?;

    // Verify old private key has ReplacementObjectLink and rotate_interval = 0.
    let old_sk = kms.database.retrieve_object(&sk_uid).await?.unwrap();
    assert_eq!(old_sk.attributes().rotate_interval, Some(0));
    let new_sk_uid = old_sk
        .attributes()
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old SK should have ReplacementObjectLink")
        .to_string();

    // Verify new private key has rotation policy.
    let new_sk = kms.database.retrieve_object(&new_sk_uid).await?.unwrap();
    assert_eq!(new_sk.attributes().rotate_interval, Some(7200));
    assert!(new_sk.attributes().initial_date.is_some());

    // Verify new private key has ReplacedObjectLink.
    let replaced = new_sk
        .attributes()
        .get_link(LinkType::ReplacedObjectLink)
        .expect("new SK should have ReplacedObjectLink")
        .to_string();
    assert_eq!(replaced, sk_uid);

    Ok(())
}

#[tokio::test]
async fn test_auto_rotate_public_key_triggers_keypair_rotation() -> KResult<()> {
    let kms = test_kms().await?;
    let (sk_uid, pk_uid) = create_active_ec_keypair(&kms).await?;

    // Set rotation policy on the PUBLIC key (simulating cron picking up PK).
    set_rotation_policy(&kms, &pk_uid, 3600).await?;

    // Trigger auto-rotation on the public key.
    auto_rotate_key(&kms, &pk_uid, OWNER).await?;

    // Verify old private key has ReplacementObjectLink (keypair was rotated).
    let old_sk = kms.database.retrieve_object(&sk_uid).await?.unwrap();
    assert!(
        old_sk
            .attributes()
            .get_link(LinkType::ReplacementObjectLink)
            .is_some(),
        "old private key should have ReplacementObjectLink after PK-triggered rotation"
    );

    // Verify old public key has rotation policy cleared.
    let old_pk = kms.database.retrieve_object(&pk_uid).await?.unwrap();
    assert_eq!(old_pk.attributes().rotate_interval, Some(0));

    Ok(())
}

// ─── Edge Cases ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_auto_rotate_nonexistent_key() -> KResult<()> {
    let kms = test_kms().await?;

    // Rotating a non-existent key should not error (just log and return Ok).
    let result = auto_rotate_key(&kms, "nonexistent-uid-12345", OWNER).await;
    result.unwrap();

    Ok(())
}

#[tokio::test]
async fn test_auto_rotate_skips_no_interval() -> KResult<()> {
    let kms = test_kms().await?;
    let key_uid = create_active_aes_key(&kms).await?;

    // No rotate_interval set → should skip.
    auto_rotate_key(&kms, &key_uid, OWNER).await?;

    let owm = kms.database.retrieve_object(&key_uid).await?.unwrap();
    assert!(
        owm.attributes()
            .get_link(LinkType::ReplacementObjectLink)
            .is_none(),
        "key without rotation policy should not be rotated"
    );

    Ok(())
}

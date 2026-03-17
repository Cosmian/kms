//! Tests for the `ModifyAttribute` KMIP operation (issue #760).
//!
//! Covers:
//! - Modifying `Name` on a Pre-Active key persists the change.
//! - Modifying `ActivationDate` to a past date on a Pre-Active key transitions to Active.
//! - Modifying `ActivationDate` to a future date on a Pre-Active key keeps it Pre-Active.
//! - Modifying `ActivationDate` on an already-Active key returns `Wrong_Key_Lifecycle_State`.

#![allow(clippy::unwrap_in_result)]

use std::{collections::HashSet, sync::Arc};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN,
            kmip_attributes::{Attribute, Attributes},
            kmip_operations::{
                GetAttributes, GetAttributesResponse, ModifyAttribute, ModifyAttributeResponse,
            },
            kmip_types::{
                AttributeReference, CryptographicAlgorithm, Name, NameType, Tag, UniqueIdentifier,
            },
            requests::create_symmetric_key_kmip_object,
        },
    },
    cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng,
        reexport::rand_core::{RngCore, SeedableRng},
    },
};
use cosmian_logger::log_init;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

const USER: &str = "eyJhbGciOiJSUzI1Ni";

// ─── helpers ────────────────────────────────────────────────────────────────

/// Create and store a fresh 256-bit AES symmetric key in the given `state`.
async fn create_key_with_state(kms: &Arc<KMS>, state: State) -> KResult<String> {
    let mut rng = CsRng::from_entropy();
    let mut key_bytes = vec![0_u8; 32];
    rng.fill_bytes(&mut key_bytes);

    let object = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(state),
            ..Attributes::default()
        },
    )?;
    let uid = Uuid::new_v4().to_string();
    kms.database
        .create(
            Some(uid.clone()),
            USER,
            &object,
            object.attributes()?,
            &HashSet::new(),
        )
        .await?;
    // Also persist the requested state in the dedicated state column.
    kms.database.update_state(&uid, state).await?;
    Ok(uid)
}

async fn get_attributes(kms: &Arc<KMS>, uid: &str, tag: Tag) -> KResult<GetAttributesResponse> {
    kms.get_attributes(
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: Some(vec![AttributeReference::Standard(tag)]),
        },
        USER,
    )
    .await
}

async fn modify_attribute(
    kms: &Arc<KMS>,
    uid: &str,
    attribute: Attribute,
) -> KResult<ModifyAttributeResponse> {
    kms.modify_attribute(
        ModifyAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            new_attribute: attribute,
        },
        USER,
    )
    .await
}

// ─── tests ──────────────────────────────────────────────────────────────────

/// The main test entry-point: sets up the KMS and runs all sub-tests.
#[tokio::test]
pub(crate) async fn test_modify_attribute_server() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    modify_name_on_pre_active_key(&kms).await?;
    modify_activation_date_past_transitions_to_active(&kms).await?;
    modify_activation_date_future_stays_pre_active(&kms).await?;
    modify_activation_date_on_active_key_rejected(&kms).await?;

    Ok(())
}

/// `ModifyAttribute(Name)` on a Pre-Active key MUST persist the name.
async fn modify_name_on_pre_active_key(kms: &Arc<KMS>) -> KResult<()> {
    let uid = create_key_with_state(kms, State::PreActive).await?;

    // No name initially.
    let resp = get_attributes(kms, &uid, Tag::Name).await?;
    assert!(resp.attributes.name.is_none());

    let name = Name {
        name_value: "synology-test-key".to_owned(),
        name_type: NameType::UninterpretedTextString,
    };
    modify_attribute(kms, &uid, Attribute::Name(name.clone())).await?;

    // Name is now persisted.
    let resp = get_attributes(kms, &uid, Tag::Name).await?;
    assert_eq!(resp.attributes.name, Some(vec![name.clone()]));

    // Replacing the name with a new one should overwrite.
    let name2 = Name {
        name_value: "renamed-key".to_owned(),
        name_type: NameType::UninterpretedTextString,
    };
    modify_attribute(kms, &uid, Attribute::Name(name2.clone())).await?;

    let resp = get_attributes(kms, &uid, Tag::Name).await?;
    let names = resp.attributes.name.expect("name must be set");
    assert_eq!(names.len(), 1, "ModifyAttribute should REPLACE, not append");
    assert_eq!(names[0], name2);

    Ok(())
}

/// `ModifyAttribute(ActivationDate)` with a date in the past on a Pre-Active key
/// MUST transition the key to Active (KMIP spec §3.22).
async fn modify_activation_date_past_transitions_to_active(kms: &Arc<KMS>) -> KResult<()> {
    let uid = create_key_with_state(kms, State::PreActive).await?;

    // A date safely in the past.
    let past = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    modify_attribute(kms, &uid, Attribute::ActivationDate(past)).await?;

    // State must now be Active.
    let resp = get_attributes(kms, &uid, Tag::State).await?;
    assert_eq!(
        resp.attributes.state,
        Some(State::Active),
        "key should have transitioned to Active after setting a past ActivationDate"
    );

    // ActivationDate is persisted.
    let resp = get_attributes(kms, &uid, Tag::ActivationDate).await?;
    assert_eq!(resp.attributes.activation_date, Some(past));

    Ok(())
}

/// `ModifyAttribute(ActivationDate)` with a date in the future on a Pre-Active key
/// MUST keep the key in Pre-Active state.
async fn modify_activation_date_future_stays_pre_active(kms: &Arc<KMS>) -> KResult<()> {
    let uid = create_key_with_state(kms, State::PreActive).await?;

    // A date far in the future.
    let future = OffsetDateTime::from_unix_timestamp(9_999_999_999).unwrap();
    modify_attribute(kms, &uid, Attribute::ActivationDate(future)).await?;

    // State must still be Pre-Active.
    let resp = get_attributes(kms, &uid, Tag::State).await?;
    assert_eq!(
        resp.attributes.state,
        Some(State::PreActive),
        "key should remain Pre-Active when ActivationDate is in the future"
    );

    // ActivationDate is still persisted.
    let resp = get_attributes(kms, &uid, Tag::ActivationDate).await?;
    assert_eq!(resp.attributes.activation_date, Some(future));

    Ok(())
}

/// `ModifyAttribute(ActivationDate)` on an already-Active key must be rejected
/// with `Wrong_Key_Lifecycle_State`.
async fn modify_activation_date_on_active_key_rejected(kms: &Arc<KMS>) -> KResult<()> {
    let uid = create_key_with_state(kms, State::Active).await?;

    let past = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    let result = modify_attribute(kms, &uid, Attribute::ActivationDate(past)).await;

    assert!(
        result.is_err(),
        "ModifyAttribute(ActivationDate) on an Active key must return an error"
    );

    Ok(())
}

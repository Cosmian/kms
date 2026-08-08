//! Tests for the server-managed `AlwaysSensitive` attribute (KMIP 2.1 §4.3).
//!
//! The `AlwaysSensitive` attribute is:
//! - created by the server (True iff the object was created `Sensitive`);
//! - read-only to clients (cannot be added, set, modified or deleted);
//! - permanently set to False once `Sensitive` has ever been set to False.
#![allow(clippy::unwrap_used, clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attribute,
        kmip_operations::{
            AddAttribute, DeleteAttribute, GetAttributes, GetAttributesResponse, ModifyAttribute,
            SetAttribute,
        },
        kmip_types::{AttributeReference, CryptographicAlgorithm, Tag, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;

use crate::{
    config::ServerParams, core::KMS, error::KmsError, result::KResult,
    tests::test_utils::https_clap_config,
};

const USER: &str = "alwayssensitive_user";

async fn instantiate_kms() -> KResult<Arc<KMS>> {
    let clap_config = https_clap_config();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?,
    ))
}

async fn create_sym_key(kms: &Arc<KMS>, sensitive: bool) -> KResult<String> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        sensitive,
        None,
    )?;
    Ok(kms
        .create(request, USER)
        .await?
        .unique_identifier
        .to_string())
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

fn assert_read_only(result: &KResult<impl std::fmt::Debug>) {
    match result {
        Err(KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _)) => {}
        other => panic!("expected Attribute_Read_Only error, got: {other:?}"),
    }
}

/// A Sensitive object is created with `AlwaysSensitive = true`; a non-sensitive
/// one with `AlwaysSensitive = false` (KMIP 2.1 §4.3).
#[tokio::test]
async fn test_always_sensitive_set_at_creation() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;

    let sensitive_uid = create_sym_key(&kms, true).await?;
    let response = get_attributes(&kms, &sensitive_uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    let plain_uid = create_sym_key(&kms, false).await?;
    let response = get_attributes(&kms, &plain_uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    Ok(())
}

/// `AlwaysSensitive` is server-managed: clients cannot Add, Set, Modify or
/// Delete it (KMIP 2.1 §4.3, Table 34).
#[tokio::test]
async fn test_always_sensitive_is_read_only() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let uid = create_sym_key(&kms, true).await?;

    let add = kms
        .add_attribute(
            AddAttribute {
                unique_identifier: UniqueIdentifier::TextString(uid.clone()),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            USER,
        )
        .await;
    assert_read_only(&add);

    let set = kms
        .set_attribute(
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            USER,
        )
        .await;
    assert_read_only(&set);

    let modify = kms
        .modify_attribute(
            ModifyAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            USER,
        )
        .await;
    assert_read_only(&modify);

    let delete_by_value = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: Some(Attribute::AlwaysSensitive(true)),
                attribute_references: None,
            },
            USER,
        )
        .await;
    assert_read_only(&delete_by_value);

    let delete_by_ref = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: None,
                attribute_references: Some(vec![AttributeReference::Standard(
                    Tag::AlwaysSensitive,
                )]),
            },
            USER,
        )
        .await;
    assert_read_only(&delete_by_ref);

    // The value must be unchanged after all rejected attempts.
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    Ok(())
}

/// Setting `Sensitive` to False permanently clears `AlwaysSensitive`, even if
/// `Sensitive` is later set back to True (KMIP 2.1 §4.3).
#[tokio::test]
async fn test_always_sensitive_derived_from_sensitive_changes() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let uid = create_sym_key(&kms, true).await?;

    // Initially always-sensitive.
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    // Set Sensitive = false -> AlwaysSensitive becomes false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Sensitive(false),
        },
        USER,
    )
    .await?;
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    // Set Sensitive = true again -> AlwaysSensitive stays false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Sensitive(true),
        },
        USER,
    )
    .await?;
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    Ok(())
}

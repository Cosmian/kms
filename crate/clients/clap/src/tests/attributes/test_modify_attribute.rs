use cosmian_kmip::time_normalize;
use cosmian_kms_client::{
    KmsClient,
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::ObjectType,
        kmip_operations::{
            Create, CreateResponse, GetAttributes, GetAttributesResponse, ModifyAttribute,
            SetAttribute,
        },
        kmip_types::{
            CryptographicAlgorithm, Name, NameType, Tag, UniqueIdentifier, VendorAttribute,
        },
    },
    reexport::cosmian_kms_client_utils::import_utils::KeyUsage,
};
use cosmian_kms_logger::trace;
use strum::IntoEnumIterator;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::{
        attributes::{
            CCryptographicAlgorithm, CLinkType, DeleteAttributesAction, GetAttributesAction,
            ModifyAttributesAction, SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli,
        },
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

fn get_all_attribute_tags() -> Vec<Tag> {
    let mut tags = Vec::new();
    for tag in Tag::iter() {
        tags.push(tag);
    }
    tags
}

fn get_all_link_types() -> Vec<CLinkType> {
    let mut links = Vec::new();
    for link_type in CLinkType::iter() {
        links.push(link_type);
    }
    links
}

async fn get_attribute_value(
    ctx: &TestsContext,
    uid: &str,
    tag: Tag,
) -> KmsCliResult<Option<serde_json::Value>> {
    let get_attributes = GetAttributesAction {
        id: Some(uid.to_owned()),
        tags: None,
        attribute_tags: get_all_attribute_tags(),
        attribute_link_types: get_all_link_types(),
        output_file: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(get_attributes.get(&tag.to_string()).cloned())
}

/// Test that `ModifyAttribute` successfully updates an existing attribute value.
///
/// The `uid` key must be an **Active** symmetric key.
async fn check_modify_attributes(uid: &str, ctx: &TestsContext) -> KmsCliResult<()> {
    let client = ctx.get_owner_client();

    // ── 1. Set initial attributes ────────────────────────────────────────────
    SetAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_length: Some(128),
            cryptographic_algorithm: Some(CCryptographicAlgorithm::AES),
            key_usage: Some(vec![KeyUsage::Encrypt]),
            vendor_attributes: Some(VendorAttributeCli {
                vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
                attribute_name: Some("my_custom_attr".to_owned()),
                attribute_value: Some("AABBCCDD".to_owned()),
            }),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    // ── 2. Modify cryptographic_length ───────────────────────────────────────
    ModifyAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_length: Some(256),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    let len_val = get_attribute_value(ctx, uid, Tag::CryptographicLength).await?;
    assert!(
        len_val.is_some(),
        "CryptographicLength should be present after modify"
    );
    let length: i32 = serde_json::from_value(len_val.unwrap())?;
    assert_eq!(
        length, 256,
        "CryptographicLength should be 256 after modify"
    );
    trace!("CryptographicLength modified successfully to 256");

    // ── 3. Modify cryptographic_algorithm ───────────────────────────────────
    ModifyAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_algorithm: Some(CCryptographicAlgorithm::Chacha20),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    let algo_val = get_attribute_value(ctx, uid, Tag::CryptographicAlgorithm).await?;
    assert!(
        algo_val.is_some(),
        "CryptographicAlgorithm should be present after modify"
    );
    let algo: CryptographicAlgorithm = serde_json::from_value(algo_val.unwrap())?;
    assert_eq!(
        algo,
        CryptographicAlgorithm::ChaCha20,
        "CryptographicAlgorithm should be ChaCha20 after modify"
    );
    trace!("CryptographicAlgorithm modified successfully to ChaCha20");

    // ── 4. Modify cryptographic_usage_mask (key_usage) ──────────────────────
    ModifyAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            key_usage: Some(vec![KeyUsage::Encrypt, KeyUsage::Decrypt]),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    let mask_val = get_attribute_value(ctx, uid, Tag::CryptographicUsageMask).await?;
    assert!(
        mask_val.is_some(),
        "CryptographicUsageMask should be present after modify"
    );
    let mask: CryptographicUsageMask = serde_json::from_value(mask_val.unwrap())?;
    assert!(
        mask.contains(CryptographicUsageMask::Encrypt),
        "CryptographicUsageMask should include Encrypt"
    );
    assert!(
        mask.contains(CryptographicUsageMask::Decrypt),
        "CryptographicUsageMask should include Decrypt"
    );
    trace!("CryptographicUsageMask modified successfully to Encrypt|Decrypt");

    // ── 5. Modify vendor_attributes ──────────────────────────────────────────
    ModifyAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            vendor_attributes: Some(VendorAttributeCli {
                vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
                attribute_name: Some("my_custom_attr".to_owned()),
                attribute_value: Some("EEFF0011".to_owned()),
            }),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    let vendor_val = get_attribute_value(ctx, uid, Tag::VendorExtension).await?;
    assert!(
        vendor_val.is_some(),
        "VendorExtension should be present after modify"
    );
    let vas: Vec<VendorAttribute> = serde_json::from_value(vendor_val.unwrap())?;
    assert!(!vas.is_empty(), "VendorExtension list should not be empty");
    trace!("VendorAttribute modified successfully");

    // ── 6. Set then modify the Name attribute (via direct KMIP API) ──────────
    let uid_ref = UniqueIdentifier::TextString(uid.to_owned());
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(uid_ref.clone()),
            new_attribute: Attribute::Name(Name {
                name_value: "initial-name".to_owned(),
                name_type: NameType::UninterpretedTextString,
            }),
        })
        .await?;

    client
        .modify_attribute(ModifyAttribute {
            unique_identifier: Some(uid_ref.clone()),
            new_attribute: Attribute::Name(Name {
                name_value: "modified-name".to_owned(),
                name_type: NameType::UninterpretedTextString,
            }),
        })
        .await?;

    let GetAttributesResponse { attributes, .. } = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(uid_ref.clone()),
            attribute_reference: None,
        })
        .await?;
    let names = attributes.name.unwrap_or_default();
    assert!(
        names.iter().any(|n| n.name_value == "modified-name"),
        "Name should contain 'modified-name' after modify, got: {names:?}"
    );
    trace!("Name attribute modified successfully to 'modified-name'");

    // ── 7. Read-only attribute: State modification MUST be rejected ──────────
    let result = client
        .modify_attribute(ModifyAttribute {
            unique_identifier: Some(uid_ref.clone()),
            new_attribute: Attribute::State(State::Active),
        })
        .await;
    assert!(
        result.is_err(),
        "ModifyAttribute(State) should be rejected as read-only"
    );
    trace!("State attribute correctly rejected as read-only");

    // ── 8. Clean up set attributes ───────────────────────────────────────────
    DeleteAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_length: Some(0),
            key_usage: Some(vec![KeyUsage::Encrypt, KeyUsage::Decrypt]),
            vendor_attributes: Some(VendorAttributeCli {
                vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
                attribute_name: Some("my_custom_attr".to_owned()),
                attribute_value: Some("EEFF0011".to_owned()),
            }),
            ..SetOrDeleteAttributes::default()
        },
        attribute_tags: None,
    }
    .process(client.clone())
    .await?;

    Ok(())
}

/// Creates a Pre-Active symmetric key with a future `activation_date`.
async fn create_preactive_symmetric_key(client: &KmsClient) -> KmsCliResult<String> {
    let future_activation = time_normalize()? + time::Duration::hours(2);
    let response: CreateResponse = client
        .create(Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                activation_date: Some(future_activation),
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                ),
                object_type: Some(ObjectType::SymmetricKey),
                ..Default::default()
            },
            protection_storage_masks: None,
        })
        .await?;
    Ok(response.unique_identifier.to_string())
}

/// Test that `activation_date` can be modified on a Pre-Active key.
///
/// `ActivationDate` can only be modified when the object is in the Pre-Active
/// state (KMIP spec §3.22). Modifying it to a past timestamp transitions the
/// object to Active.
async fn check_modify_activation_date(ctx: &TestsContext) -> KmsCliResult<()> {
    let client = ctx.get_owner_client();
    let uid = create_preactive_symmetric_key(&client).await?;

    // Set the initial activation_date to 2 hours in the future.
    let initial_ts = (time_normalize()? + time::Duration::hours(2)).unix_timestamp();
    SetAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.clone()),
            activation_date: Some(initial_ts),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    // Modify to 3 hours in the future.
    let new_ts = (time_normalize()? + time::Duration::hours(3)).unix_timestamp();
    ModifyAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.clone()),
            activation_date: Some(new_ts),
            ..SetOrDeleteAttributes::default()
        },
    }
    .process(client.clone())
    .await?;

    let date_val = get_attribute_value(ctx, &uid, Tag::ActivationDate).await?;
    assert!(
        date_val.is_some(),
        "ActivationDate should be present after modify on Pre-Active key"
    );
    let stored_ts: i64 = serde_json::from_value(date_val.unwrap())?;
    assert_eq!(
        stored_ts, new_ts,
        "ActivationDate should equal new_ts after modify"
    );
    trace!("ActivationDate modified successfully on Pre-Active key");

    Ok(())
}

/// Test `ModifyAttribute` on a symmetric key and verify the changes are persisted.
///
/// # Errors
///
/// Returns an error if the KMS server cannot be started or if any attribute operation fails.
#[tokio::test]
async fn test_modify_attribute() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    let uid = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    check_modify_attributes(uid.as_str().unwrap(), ctx).await?;
    check_modify_activation_date(ctx).await?;

    Ok(())
}

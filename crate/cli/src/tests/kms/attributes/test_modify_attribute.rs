use cosmian_kms_client::{
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_types::{Tag, VendorAttribute},
    },
    reexport::cosmian_kms_client_utils::import_utils::KeyUsage,
};
use cosmian_logger::trace;
use strum::IntoEnumIterator;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::{
        attributes::{
            CLinkType, DeleteAttributesAction, GetAttributesAction, ModifyAttributesAction,
            SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli,
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
async fn check_modify_attributes(uid: &str, ctx: &TestsContext) -> KmsCliResult<()> {
    // ── 1. Set initial attributes with SetAttribute ──────────────────────────
    let initial_attrs = SetOrDeleteAttributes {
        id: Some(uid.to_owned()),
        activation_date: Some(5),
        cryptographic_length: Some(128),
        key_usage: Some(vec![KeyUsage::Encrypt]),
        vendor_attributes: Some(VendorAttributeCli {
            vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
            attribute_name: Some("my_custom_attr".to_owned()),
            attribute_value: Some("AABBCCDD".to_owned()),
        }),
        ..SetOrDeleteAttributes::default()
    };
    SetAttributesAction {
        requested_attributes: initial_attrs.clone(),
    }
    .process(ctx.get_owner_client())
    .await?;

    // ── 2. Modify activation_date ────────────────────────────────────────────
    let modify_date = SetOrDeleteAttributes {
        id: Some(uid.to_owned()),
        activation_date: Some(100),
        ..SetOrDeleteAttributes::default()
    };
    ModifyAttributesAction {
        requested_attributes: modify_date.clone(),
    }
    .process(ctx.get_owner_client())
    .await?;

    let date_val = get_attribute_value(ctx, uid, Tag::ActivationDate).await?;
    assert!(
        date_val.is_some(),
        "ActivationDate attribute should be present after modify"
    );
    let date: i64 = serde_json::from_value(date_val.unwrap())?;
    assert_eq!(date, 100, "ActivationDate should be 100 after modify");
    trace!("ActivationDate modified successfully to 100");

    // ── 3. Modify cryptographic_length ───────────────────────────────────────
    let modify_length = SetOrDeleteAttributes {
        id: Some(uid.to_owned()),
        cryptographic_length: Some(256),
        ..SetOrDeleteAttributes::default()
    };
    ModifyAttributesAction {
        requested_attributes: modify_length,
    }
    .process(ctx.get_owner_client())
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

    // ── 4. Modify vendor_attributes ──────────────────────────────────────────
    let modify_vendor = SetOrDeleteAttributes {
        id: Some(uid.to_owned()),
        vendor_attributes: Some(VendorAttributeCli {
            vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
            attribute_name: Some("my_custom_attr".to_owned()),
            attribute_value: Some("EEFF0011".to_owned()),
        }),
        ..SetOrDeleteAttributes::default()
    };
    ModifyAttributesAction {
        requested_attributes: modify_vendor,
    }
    .process(ctx.get_owner_client())
    .await?;

    let vendor_val = get_attribute_value(ctx, uid, Tag::VendorExtension).await?;
    assert!(
        vendor_val.is_some(),
        "VendorExtension should be present after modify"
    );
    let vas: Vec<VendorAttribute> = serde_json::from_value(vendor_val.unwrap())?;
    assert!(!vas.is_empty(), "VendorExtension list should not be empty");
    trace!("VendorAttribute modified successfully");

    // ── 5. Clean up ──────────────────────────────────────────────────────────
    DeleteAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            activation_date: Some(0), // any value — only key matters for deletion
            cryptographic_length: Some(0),
            key_usage: Some(vec![KeyUsage::Encrypt]),
            vendor_attributes: Some(VendorAttributeCli {
                vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
                attribute_name: Some("my_custom_attr".to_owned()),
                attribute_value: Some("EEFF0011".to_owned()),
            }),
            ..SetOrDeleteAttributes::default()
        },
        attribute_tags: None,
    }
    .process(ctx.get_owner_client())
    .await?;

    Ok(())
}

/// Test `ModifyAttribute` on a symmetric key and verify the changes are persisted.
///
/// # Errors
///
/// Returns an error if the KMS server cannot be started or if any attribute operation fails.
#[ignore = "Too much verbosity"]
#[tokio::test]
async fn test_modify_attribute() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    let uid = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    check_modify_attributes(uid.as_str().unwrap(), ctx).await?;

    Ok(())
}

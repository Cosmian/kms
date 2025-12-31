use cosmian_kms_client::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_types::{CryptographicAlgorithm, LinkType, Tag, VendorAttribute},
    },
    reexport::cosmian_kms_client_utils::{
        certificate_utils::Algorithm,
        import_utils::{KeyUsage, build_usage_mask_from_key_usage},
    },
};
use cosmian_logger::trace;
use strum::IntoEnumIterator;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::{
        attributes::{
            CCryptographicAlgorithm, CLinkType, DeleteAttributesAction, GetAttributesAction,
            SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli,
        },
        certificates::certify::CertifyAction,
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

async fn get_and_check_attributes(
    ctx: &TestsContext,
    uid: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> KmsCliResult<()> {
    let get_attributes = GetAttributesAction {
        id: Some(uid.to_owned()),
        tags: None,
        attribute_tags: get_all_attribute_tags(),
        attribute_link_types: get_all_link_types(),
        output_file: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    trace!("{get_attributes:?}");

    if let Some(activation_date) = requested_attributes.activation_date {
        let date: i64 =
            serde_json::from_value(get_attributes[&Tag::ActivationDate.to_string()].clone())?;

        assert_eq!(date, activation_date);
    }
    if let Some(cryptographic_length) = requested_attributes.cryptographic_length {
        let length: i32 =
            serde_json::from_value(get_attributes[&Tag::CryptographicLength.to_string()].clone())?;
        assert_eq!(length, cryptographic_length);
    }
    if let Some(cryptographic_algorithm) = requested_attributes.cryptographic_algorithm {
        let algo: CryptographicAlgorithm = serde_json::from_value(
            get_attributes[&Tag::CryptographicAlgorithm.to_string()].clone(),
        )?;
        assert_eq!(algo, cryptographic_algorithm.into());
    }
    if let Some(key_usage) = &requested_attributes.key_usage {
        let get_key_usage: CryptographicUsageMask = serde_json::from_value(
            get_attributes[&Tag::CryptographicUsageMask.to_string()].clone(),
        )?;
        assert_eq!(
            get_key_usage,
            build_usage_mask_from_key_usage(key_usage).unwrap()
        );
    }
    if let Some(public_key_id) = &requested_attributes.public_key_id {
        let id: String =
            serde_json::from_value(get_attributes[&LinkType::PublicKeyLink.to_string()].clone())?;
        assert_eq!(&id, public_key_id);
    }
    if let Some(private_key_id) = &requested_attributes.private_key_id {
        let id: String =
            serde_json::from_value(get_attributes[&LinkType::PrivateKeyLink.to_string()].clone())?;
        assert_eq!(&id, private_key_id);
    }
    if let Some(certificate_id) = &requested_attributes.certificate_id {
        let certificate_link_id: String =
            serde_json::from_value(get_attributes[&LinkType::CertificateLink.to_string()].clone())?;
        assert_eq!(certificate_id, &certificate_link_id);
    }
    if let Some(pkcs12_certificate_id) = &requested_attributes.pkcs12_certificate_id {
        let pkcs12_id: String = serde_json::from_value(
            get_attributes[&LinkType::PKCS12CertificateLink.to_string()].clone(),
        )?;

        assert_eq!(&pkcs12_id, pkcs12_certificate_id);
    }
    if let Some(pkcs12_password_certificate) = &requested_attributes.pkcs12_password_certificate {
        let pkcs12_password_link: String = serde_json::from_value(
            get_attributes[&LinkType::PKCS12PasswordLink.to_string()].clone(),
        )?;
        assert_eq!(&pkcs12_password_link, pkcs12_password_certificate);
    }
    if let Some(vendor_attributes) = &requested_attributes.vendor_attributes {
        let vendor_attributes_: Vec<VendorAttribute> =
            serde_json::from_value(get_attributes[&Tag::VendorExtension.to_string()].clone())?;
        let input_vendor_attributes = [VendorAttribute::try_from(vendor_attributes)?];
        assert_eq!(vendor_attributes_.len(), input_vendor_attributes.len());
        for (a, b) in vendor_attributes_
            .iter()
            .zip(input_vendor_attributes.iter())
        {
            assert_eq!(a, b);
        }
    }

    Ok(())
}

async fn get_and_check_none_attributes(
    ctx: &TestsContext,
    uid: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> KmsCliResult<()> {
    let get_attributes = GetAttributesAction {
        id: Some(uid.to_owned()),
        tags: None,
        attribute_tags: get_all_attribute_tags(),
        attribute_link_types: get_all_link_types(),
        output_file: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    trace!("{get_attributes:?}");

    if let Some(_activation_date) = requested_attributes.activation_date {
        assert!(!get_attributes.contains_key(&Tag::ActivationDate.to_string()));
    }
    if let Some(_cryptographic_length) = requested_attributes.cryptographic_length {
        assert!(!get_attributes.contains_key(&Tag::CryptographicLength.to_string()));
    }
    if let Some(_cryptographic_algorithm) = requested_attributes.cryptographic_algorithm {
        assert!(!get_attributes.contains_key(&Tag::CryptographicAlgorithm.to_string()));
    }
    if let Some(_key_usage) = &requested_attributes.key_usage {
        assert!(!get_attributes.contains_key(&Tag::CryptographicUsageMask.to_string()));
    }
    if let Some(_public_key_id) = &requested_attributes.public_key_id {
        assert!(!get_attributes.contains_key(&LinkType::PublicKeyLink.to_string()));
    }
    if let Some(_private_key_id) = &requested_attributes.private_key_id {
        assert!(!get_attributes.contains_key(&LinkType::PrivateKeyLink.to_string()));
    }
    if let Some(_certificate_id) = &requested_attributes.certificate_id {
        assert!(!get_attributes.contains_key(&LinkType::CertificateLink.to_string()));
    }
    if let Some(_pkcs12_certificate_id) = &requested_attributes.pkcs12_certificate_id {
        assert!(!get_attributes.contains_key(&LinkType::PKCS12CertificateLink.to_string()));
    }
    if let Some(_pkcs12_password_certificate) = &requested_attributes.pkcs12_password_certificate {
        assert!(!get_attributes.contains_key(&LinkType::PKCS12PasswordLink.to_string()));
    }
    if let Some(_vendor_attributes) = &requested_attributes.vendor_attributes {
        assert!(!get_attributes.contains_key(&Tag::VendorExtension.to_string()));
    }

    Ok(())
}

async fn check_set_delete_attributes(uid: &str, ctx: &TestsContext) -> KmsCliResult<()> {
    let key_usage = Some(vec![KeyUsage::Encrypt, KeyUsage::Decrypt]);
    for activation_date in [None, Some(5)] {
        for cryptographic_length in [None, Some(256)] {
            let requested_attributes = SetOrDeleteAttributes {
                id: Some(uid.to_owned()),
                activation_date,
                cryptographic_length,
                key_usage: key_usage.clone(),
                public_key_id: Some("public_key_id".to_owned()),
                private_key_id: Some("private_key_id".to_owned()),
                certificate_id: Some("certificate_id".to_owned()),
                pkcs12_certificate_id: Some("pkcs12_certificate_id".to_owned()),
                pkcs12_password_certificate: Some("toto".to_owned()),
                parent_id: Some("parent_id".to_owned()),
                child_id: Some("child_id".to_owned()),
                vendor_attributes: Some(VendorAttributeCli {
                    vendor_identification: Some(VENDOR_ID_COSMIAN.to_owned()),
                    attribute_name: Some("my_new_attribute".to_owned()),
                    attribute_value: Some("AABBCCDDEEFF".to_owned()),
                }),
                ..SetOrDeleteAttributes::default()
            };

            // Set attributes
            SetAttributesAction {
                requested_attributes: requested_attributes.clone(),
            }
            .process(ctx.get_owner_client())
            .await?;

            // Get and check attributes
            get_and_check_attributes(ctx, uid, &requested_attributes).await?;

            // Delete attributes
            DeleteAttributesAction {
                requested_attributes: requested_attributes.clone(),
                attribute_tags: None,
            }
            .process(ctx.get_owner_client())
            .await?;

            // Get and check none attributes
            get_and_check_none_attributes(ctx, uid, &requested_attributes).await?;
        }
    }

    // Test cryptographic algorithm one by one
    for cryptographic_algorithm in CCryptographicAlgorithm::iter() {
        let requested_attributes = SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_algorithm: Some(cryptographic_algorithm),
            ..SetOrDeleteAttributes::default()
        };

        // Set attributes
        SetAttributesAction {
            requested_attributes: requested_attributes.clone(),
        }
        .process(ctx.get_owner_client())
        .await?;

        // Get and check attributes
        get_and_check_attributes(ctx, uid, &requested_attributes).await?;

        // Delete attributes
        DeleteAttributesAction {
            requested_attributes: requested_attributes.clone(),
            attribute_tags: None,
        }
        .process(ctx.get_owner_client())
        .await?;

        // Get and check none attributes
        get_and_check_none_attributes(ctx, uid, &requested_attributes).await?;
    }

    // Test key usage one by one
    for key_usage in KeyUsage::iter() {
        let requested_attributes = SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            key_usage: Some(vec![key_usage.clone()]),
            ..SetOrDeleteAttributes::default()
        };
        // Set attributes
        SetAttributesAction {
            requested_attributes: requested_attributes.clone(),
        }
        .process(ctx.get_owner_client())
        .await?;

        // Get and check attributes
        get_and_check_attributes(ctx, uid, &requested_attributes).await?;

        // Delete attributes
        DeleteAttributesAction {
            requested_attributes: requested_attributes.clone(),
            attribute_tags: None,
        }
        .process(ctx.get_owner_client())
        .await?;

        // Get and check none attributes
        get_and_check_none_attributes(ctx, uid, &requested_attributes).await?;
    }

    trace!("Test delete all attributes by references");
    for tag in Tag::iter() {
        DeleteAttributesAction {
            requested_attributes: SetOrDeleteAttributes {
                id: Some(uid.to_owned()),
                ..SetOrDeleteAttributes::default()
            },
            attribute_tags: Some(vec![tag]),
        }
        .process(ctx.get_owner_client())
        .await?;
    }

    // Accumulate all values of AttributeTag in a Vec
    let mut attribute_tags = Vec::new();
    for tag in Tag::iter() {
        attribute_tags.push(tag);
    }

    DeleteAttributesAction {
        requested_attributes: SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            ..SetOrDeleteAttributes::default()
        },
        attribute_tags: Some(attribute_tags),
    }
    .process(ctx.get_owner_client())
    .await?;

    Ok(())
}

/// This asynchronous test function performs a series of operations to validate the setting,
/// getting, and deleting of attributes in a Key Management System (KMS) server. It follows
/// these steps:
///
/// 1. Starts a default test KMS server.
/// 2. Creates an AES 256-bit symmetric key and verifies its attributes.
/// 3. Certifies a Certificate Signing Request (CSR) without an issuer (self-signed) and verifies its attributes.
///
/// The function uses various helper functions to set, get, and delete attributes, and checks
/// the correctness of these operations by comparing the expected and actual values.
///
/// # Returns
///
/// This function returns a `KmsCliResult<()>`, which is an alias for `Result<(), KmsCliError>`.
///
/// # Errors
///
/// This function will return an error if any of the attribute operations (set, get, delete)
/// fail or if the test KMS server fails to start.
/// ```
#[ignore = "too much verbosity"]
#[tokio::test]
async fn test_set_attribute() -> KmsCliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // AES 256 bit key
    let uid = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    check_set_delete_attributes(uid.as_str().unwrap(), ctx).await?;

    // Issue self signed certificate
    let uid = CertifyAction {
        generate_key_pair: true,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        algorithm: Algorithm::NistP256,
        tags: vec!["certify_self_signed".to_owned()],
        ..CertifyAction::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    check_set_delete_attributes(uid.as_str().unwrap(), ctx).await?;

    Ok(())
}

use cosmian_kms_client::kmip::{
    extra::VENDOR_ID_COSMIAN,
    kmip_types::{CryptographicAlgorithm, CryptographicUsageMask, LinkType, Tag, VendorAttribute},
};
use kms_test_server::{start_default_test_kms_server, TestsContext};
use strum::IntoEnumIterator;
use tracing::trace;

use crate::{
    actions::{
        attributes::{SetOrDeleteAttributes, VendorAttributeCli},
        certificates::Algorithm,
        shared::utils::{build_usage_mask_from_key_usage, KeyUsage},
    },
    error::result::CliResult,
    tests::{
        attributes::{delete::delete_attributes, get::get_attributes, set::set_attributes},
        certificates::certify::{certify, CertifyOp},
        symmetric::create_key::create_symmetric_key,
    },
};

fn get_all_attribute_tags() -> Vec<Tag> {
    let mut tags = Vec::new();
    for tag in Tag::iter() {
        tags.push(tag);
    }
    tags
}

fn get_all_link_types() -> Vec<LinkType> {
    let mut links = Vec::new();
    for link_type in LinkType::iter() {
        links.push(link_type);
    }
    links
}

#[allow(clippy::cognitive_complexity)]
fn get_and_check_attributes(
    ctx: &TestsContext,
    uid: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> CliResult<()> {
    let get_attributes = get_attributes(
        &ctx.owner_client_conf_path,
        uid,
        &get_all_attribute_tags(),
        &get_all_link_types(),
    )?;
    trace!("get_and_check_attributes: {get_attributes:?}");

    if let Some(activation_date) = requested_attributes.activation_date {
        let date: u64 = serde_json::from_value(
            get_attributes
                .get(&Tag::ActivationDate.to_string())
                .unwrap()
                .clone(),
        )?;

        assert_eq!(date, activation_date);
    }
    if let Some(cryptographic_length) = requested_attributes.cryptographic_length {
        let length: i32 = serde_json::from_value(
            get_attributes
                .get(&Tag::CryptographicLength.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(length, cryptographic_length);
    }
    if let Some(cryptographic_algorithm) = requested_attributes.cryptographic_algorithm {
        let algo: CryptographicAlgorithm = serde_json::from_value(
            get_attributes
                .get(&Tag::CryptographicAlgorithm.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(algo, cryptographic_algorithm);
    }
    if let Some(key_usage) = &requested_attributes.key_usage {
        let get_key_usage: CryptographicUsageMask = serde_json::from_value(
            get_attributes
                .get(&Tag::CryptographicUsageMask.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(
            get_key_usage,
            build_usage_mask_from_key_usage(key_usage).unwrap()
        );
    }
    if let Some(public_key_id) = &requested_attributes.public_key_id {
        let id: String = serde_json::from_value(
            get_attributes
                .get(&LinkType::PublicKeyLink.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(&id, public_key_id);
    }
    if let Some(private_key_id) = &requested_attributes.private_key_id {
        let id: String = serde_json::from_value(
            get_attributes
                .get(&LinkType::PrivateKeyLink.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(&id, private_key_id);
    }
    if let Some(certificate_id) = &requested_attributes.certificate_id {
        let certificate_link_id: String = serde_json::from_value(
            get_attributes
                .get(&LinkType::CertificateLink.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(certificate_id, &certificate_link_id);
    }
    if let Some(pkcs12_certificate_id) = &requested_attributes.pkcs12_certificate_id {
        let pkcs12_id: String = serde_json::from_value(
            get_attributes
                .get(&LinkType::PKCS12CertificateLink.to_string())
                .unwrap()
                .clone(),
        )?;

        assert_eq!(&pkcs12_id, pkcs12_certificate_id);
    }
    if let Some(pkcs12_password_certificate) = &requested_attributes.pkcs12_password_certificate {
        let pkcs12_password_link: String = serde_json::from_value(
            get_attributes
                .get(&LinkType::PKCS12PasswordLink.to_string())
                .unwrap()
                .clone(),
        )?;
        assert_eq!(&pkcs12_password_link, pkcs12_password_certificate);
    }
    if let Some(vendor_attributes) = &requested_attributes.vendor_attributes {
        let vendor_attributes_: Vec<VendorAttribute> = serde_json::from_value(
            get_attributes
                .get(&Tag::VendorExtension.to_string())
                .unwrap()
                .clone(),
        )?;
        let input_vendor_attributes = vec![VendorAttribute::try_from(vendor_attributes)?];
        assert_eq!(vendor_attributes_, input_vendor_attributes);
    }

    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn get_and_check_none_attributes(
    ctx: &TestsContext,
    uid: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> CliResult<()> {
    let get_attributes = get_attributes(
        &ctx.owner_client_conf_path,
        uid,
        &get_all_attribute_tags(),
        &get_all_link_types(),
    )?;
    trace!("get_and_check_attributes: {get_attributes:?}");

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

fn check_set_delete_attributes(uid: &str, ctx: &TestsContext) -> CliResult<()> {
    let key_usage = Some(vec![KeyUsage::Encrypt, KeyUsage::Decrypt]);
    for activation_date in [None, Some(5)] {
        for cryptographic_length in [None, Some(256)] {
            let requested_attributes = SetOrDeleteAttributes {
                id: Some(uid.to_owned()),
                activation_date,
                cryptographic_length,
                key_usage: key_usage.clone(),
                public_key_id: Some("public_key_id".to_string()),
                private_key_id: Some("private_key_id".to_string()),
                certificate_id: Some("certificate_id".to_string()),
                pkcs12_certificate_id: Some("pkcs12_certificate_id".to_string()),
                pkcs12_password_certificate: Some("toto".to_string()),
                parent_id: Some("parent_id".to_string()),
                child_id: Some("child_id".to_string()),
                vendor_attributes: Some(VendorAttributeCli {
                    vendor_identification: Some(VENDOR_ID_COSMIAN.to_string()),
                    attribute_name: Some("my_new_attribute".to_string()),
                    attribute_value: Some("AABBCCDDEEFF".to_string()),
                }),
                ..SetOrDeleteAttributes::default()
            };
            set_attributes(&ctx.owner_client_conf_path, &requested_attributes)?;
            get_and_check_attributes(ctx, uid, &requested_attributes)?;
            delete_attributes(
                &ctx.owner_client_conf_path,
                Some(&requested_attributes),
                None,
            )?;
            get_and_check_none_attributes(ctx, uid, &requested_attributes)?;
        }
    }

    // Test cryptographic algorithm one by one
    for cryptographic_algorithm in CryptographicAlgorithm::iter() {
        let requested_attributes = SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            cryptographic_algorithm: Some(cryptographic_algorithm),
            ..SetOrDeleteAttributes::default()
        };

        set_attributes(&ctx.owner_client_conf_path, &requested_attributes)?;
        get_and_check_attributes(ctx, uid, &requested_attributes)?;
        delete_attributes(
            &ctx.owner_client_conf_path,
            Some(&requested_attributes),
            None,
        )?;
        get_and_check_none_attributes(ctx, uid, &requested_attributes)?;
    }

    // Test key usage one by one
    for key_usage in KeyUsage::iter() {
        let requested_attributes = SetOrDeleteAttributes {
            id: Some(uid.to_owned()),
            key_usage: Some(vec![key_usage.clone()]),
            ..SetOrDeleteAttributes::default()
        };
        set_attributes(&ctx.owner_client_conf_path, &requested_attributes)?;
        get_and_check_attributes(ctx, uid, &requested_attributes)?;
        delete_attributes(
            &ctx.owner_client_conf_path,
            Some(&requested_attributes),
            None,
        )?;
        get_and_check_none_attributes(ctx, uid, &requested_attributes)?;
    }

    trace!("Test delete all attributes by references");
    let requested_attributes = Some(SetOrDeleteAttributes {
        id: Some(uid.to_owned()),
        ..SetOrDeleteAttributes::default()
    });
    for tag in Tag::iter() {
        delete_attributes(
            &ctx.owner_client_conf_path,
            requested_attributes.as_ref(),
            Some(vec![tag]),
        )?;
    }

    // Accumulate all values of AttributeTag in a Vec
    let mut attribute_tags = Vec::new();
    for tag in Tag::iter() {
        attribute_tags.push(tag);
    }
    delete_attributes(
        &ctx.owner_client_conf_path,
        requested_attributes.as_ref(),
        Some(attribute_tags),
    )?;
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
/// This function returns a `CliResult<()>`, which is an alias for `Result<(), CliError>`.
///
/// # Errors
///
/// This function will return an error if any of the attribute operations (set, get, delete)
/// fail or if the test KMS server fails to start.
/// ```
#[tokio::test]
async fn test_set_attribute_ckms() -> CliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // AES 256 bit key
    let uid = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    check_set_delete_attributes(&uid, ctx)?;

    // Certify the CSR without issuer i.e. self signed
    let uid = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_string(),
            ),
            tags: Some(vec!["certify_self_signed".to_owned()]),
            ..Default::default()
        },
    )?;
    check_set_delete_attributes(&uid, ctx)?;

    Ok(())
}

//! This module contains tests for setting and removing attributes on a KMIP server.
//!
//! The tests cover various attributes including activation date, cryptographic algorithm,
//! cryptographic length, and link attributes. Each test follows a similar pattern:
//! 1. Verify the attribute is not set initially.
//! 2. Set the attribute.
//! 3. Verify the attribute is set correctly.
//! 4. Remove the attribute.
//! 5. Verify the attribute is removed.
//!
//! The tests use the `KMS` to perform operations and the `GetAttributesResponse` to
//! verify the state of attributes.
//!
//! # Constants
//! - `USER`: A constant string representing the user identifier.
//!
//! # Functions
//! - `get_attributes`: Asynchronously retrieves attributes from the KMIP server.
//! - `set_attribute`: Asynchronously sets an attribute on the KMIP server.
//! - `test_set_attribute_server`: The main test function that initializes the server and runs all attribute tests.
//! - `set_activation_date_and_remove_it`: Tests setting and removing the activation date attribute.
//! - `set_link_attribute_and_remove_it`: Tests setting and removing link attributes.
//! - `set_cryptographic_algorithm_and_remove_it`: Tests setting and removing the cryptographic algorithm attribute.
//! - `set_cryptographic_length_and_remove_it`: Tests setting and removing the cryptographic length attribute.

use std::{collections::HashSet, sync::Arc};

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_operations::{DeleteAttribute, GetAttributes, GetAttributesResponse, SetAttribute},
        kmip_types::{
            Attribute, AttributeReference, CryptographicAlgorithm, Link, LinkType,
            LinkedObjectIdentifier, Tag, UniqueIdentifier,
        },
    },
};
use cosmian_logger::log_utils::log_init;
use uuid::Uuid;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

const USER: &str = "eyJhbGciOiJSUzI1Ni";

async fn get_attributes(kms: &Arc<KMS>, uid: &str, tag: Tag) -> KResult<GetAttributesResponse> {
    kms.get_attributes(
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_references: Some(vec![AttributeReference::Standard(tag)]),
        },
        USER,
        None,
    )
    .await
}

async fn set_attribute(kms: &Arc<KMS>, uid: &str, attribute: Attribute) -> KResult<()> {
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            new_attribute: attribute,
        },
        USER,
        None,
    )
    .await?;
    Ok(())
}

async fn delete_attribute(kms: &Arc<KMS>, delete_request: DeleteAttribute) -> KResult<()> {
    kms.delete_attribute(delete_request, USER, None).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_attribute_server() -> KResult<()> {
    log_init(None);

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);

    let mut rng = CsRng::from_entropy();

    // Create key
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let sym_key_object = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        CryptographicAlgorithm::AES,
        false,
    )?;
    let uid = Uuid::new_v4().to_string();

    kms.database
        .create(
            Some(uid.clone()),
            USER,
            &sym_key_object,
            sym_key_object.attributes()?,
            &HashSet::new(),
            None,
        )
        .await?;

    //
    // Start tests
    //
    set_activation_date_and_remove_it(
        &kms,
        &uid,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            current_attribute: Some(Attribute::ActivationDate(42)),
            attribute_references: None,
        },
    )
    .await?;
    set_activation_date_and_remove_it(
        &kms,
        &uid,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            current_attribute: None,
            attribute_references: Some(vec![AttributeReference::Standard(Tag::ActivationDate)]),
        },
    )
    .await?;
    set_cryptographic_algorithm_and_remove_it(&kms, &uid).await?;
    set_cryptographic_length_and_remove_it(&kms, &uid).await?;
    set_link_attribute_and_remove_it(&kms, &uid, Tag::LinkType, LinkType::CertificateLink).await?;
    set_link_attribute_and_remove_it(&kms, &uid, Tag::LinkType, LinkType::PKCS12CertificateLink)
        .await?;
    set_link_attribute_and_remove_it(&kms, &uid, Tag::LinkType, LinkType::PrivateKeyLink).await?;
    set_link_attribute_and_remove_it(&kms, &uid, Tag::LinkType, LinkType::PublicKeyLink).await?;

    Ok(())
}

async fn set_activation_date_and_remove_it(
    kms: &Arc<KMS>,
    uid: &str,
    delete_request: DeleteAttribute,
) -> KResult<()> {
    // Check no activation date is set
    let get_response = get_attributes(kms, uid, Tag::ActivationDate).await?;
    assert!(get_response.attributes.activation_date.is_none());

    // Set activation date
    set_attribute(kms, uid, Attribute::ActivationDate(42)).await?;
    // and check if it is set correctly
    let get_response = get_attributes(kms, uid, Tag::ActivationDate).await?;
    assert_eq!(get_response.attributes.activation_date, Some(42));
    // Remove activation date
    delete_attribute(kms, delete_request).await?;
    // and check if it is removed
    let get_response = get_attributes(kms, uid, Tag::ActivationDate).await?;
    assert!(get_response.attributes.activation_date.is_none());

    Ok(())
}

async fn set_link_attribute_and_remove_it(
    kms: &Arc<KMS>,
    uid: &str,
    tag: Tag,
    link_type: LinkType,
) -> KResult<()> {
    // Check no link attribute is set
    let get_response = get_attributes(kms, uid, tag).await?;
    assert!(get_response.attributes.link.is_none());

    let links = vec![Link {
        link_type,
        linked_object_identifier: LinkedObjectIdentifier::TextString("my_link".to_owned()),
    }];
    set_attribute(kms, uid, Attribute::Links(links.clone())).await?;

    let get_response = get_attributes(kms, uid, tag).await?;
    assert_eq!(get_response.attributes.link, Some(links));

    kms.delete_attribute(
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_references: Some(vec![AttributeReference::Standard(tag)]),
            ..DeleteAttribute::default()
        },
        USER,
        None,
    )
    .await?;

    let get_response = get_attributes(kms, uid, tag).await?;
    assert!(get_response.attributes.link.is_none());

    Ok(())
}

async fn set_cryptographic_algorithm_and_remove_it(kms: &Arc<KMS>, uid: &str) -> KResult<()> {
    // Check no cryptographic algorithm is set
    let get_response = get_attributes(kms, uid, Tag::CryptographicAlgorithm).await?;

    assert_eq!(
        get_response.attributes.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );

    set_attribute(
        kms,
        uid,
        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
    )
    .await?;

    let get_response = get_attributes(kms, uid, Tag::CryptographicAlgorithm).await?;
    assert_eq!(
        get_response.attributes.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );

    delete_attribute(
        kms,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            current_attribute: Some(Attribute::CryptographicAlgorithm(
                CryptographicAlgorithm::AES,
            )),
            attribute_references: None,
        },
    )
    .await?;

    let get_response = get_attributes(kms, uid, Tag::CryptographicAlgorithm).await?;
    assert!(get_response.attributes.cryptographic_algorithm.is_none());

    Ok(())
}

async fn set_cryptographic_length_and_remove_it(kms: &Arc<KMS>, uid: &str) -> KResult<()> {
    // Check no cryptographic length is set
    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert_eq!(get_response.attributes.cryptographic_length, Some(256));

    set_attribute(kms, uid, Attribute::CryptographicLength(256)).await?;

    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert_eq!(get_response.attributes.cryptographic_length, Some(256));

    delete_attribute(
        kms,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            current_attribute: Some(Attribute::CryptographicLength(256)),
            attribute_references: None,
        },
    )
    .await?;

    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert!(get_response.attributes.cryptographic_length.is_none());

    Ok(())
}

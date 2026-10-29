//! This module contains tests for setting and removing attributes on a KMIP server.
//!
//! The tests cover various attributes including activation date, cryptographic algorithm,
//! cryptographic length, and link attributes. Each test follows a similar pattern:
//! 1. Verify the attribute is not set initially.
//! 2. Set the attribute.

#![allow(clippy::unwrap_in_result)]
//! 3. Verify the attribute is set correctly.
//! 4. Remove the attribute.
//! 5. Verify the attribute is removed.
//!
//! The tests use the `KMS` to perform operations and the `GetAttributesResponse` to
//! verify the state of attributes.
//!
//! # Constants
//! - `&UserId::from(USER)`: A constant string representing the user identifier.
//!
//! # Functions
//! - `get_attributes`: Asynchronously retrieves attributes from the KMIP server.
//! - `set_attribute`: Asynchronously sets an attribute on the KMIP server.
//! - `test_set_attribute_server`: The main test function that initializes the server and runs all attribute tests.
//! - `set_activation_date_and_remove_it`: Tests setting and removing the activation date attribute.
//! - `set_link_attribute_and_remove_it`: Tests setting and removing link attributes.
//! - `set_cryptographic_algorithm_is_rejected_as_read_only`: Tests that setting or deleting the cryptographic algorithm is refused.
//! - `set_cryptographic_length_is_rejected_as_read_only`: Tests that setting or deleting the cryptographic length is refused.
//! - `server_managed_attributes_are_rejected`: Tests that Add/Set/Modify/DeleteAttribute refuse every read-only attribute with the KMIP result reason of each operation and leave the object unchanged.

use std::{collections::HashSet, sync::Arc};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN,
            kmip_attributes::{Attribute, Attributes},
            kmip_objects::ObjectType,
            kmip_operations::{
                AddAttribute, DeleteAttribute, GetAttributes, GetAttributesResponse,
                ModifyAttribute, SetAttribute,
            },
            kmip_types::{
                AttributeReference, CryptographicAlgorithm, CryptographicDomainParameters, Digest,
                DigitalSignatureAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
                RecommendedCurve, Tag, UniqueIdentifier,
            },
            requests::create_symmetric_key_kmip_object,
        },
    },
    cosmian_kms_crypto::{
        crypto::KmsRng, reexport::cosmian_crypto_core::reexport::rand_core::RngCore,
    },
};
use cosmian_logger::log_init;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::KMS, error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms,
};

const USER: &str = "eyJhbGciOiJSUzI1Ni";

async fn get_attributes(kms: &Arc<KMS>, uid: &str, tag: Tag) -> KResult<GetAttributesResponse> {
    kms.get_attributes(
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: Some(vec![AttributeReference::Standard(tag)]),
        },
        &UserId::from(USER),
    )
    .await
}

async fn set_attribute(kms: &Arc<KMS>, uid: &str, attribute: Attribute) -> KResult<()> {
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            new_attribute: attribute,
        },
        &UserId::from(USER),
    )
    .await?;
    Ok(())
}

async fn delete_attribute(kms: &Arc<KMS>, delete_request: DeleteAttribute) -> KResult<()> {
    kms.delete_attribute(delete_request, &UserId::from(USER))
        .await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_attribute_server() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let kms = test_kms().await?;

    let mut rng = KmsRng::new().seeded_csrng()?;

    // Create key
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let sym_key_object = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )?;
    let uid = Uuid::new_v4().to_string();

    kms.database
        .create(
            Some(uid.clone()),
            &UserId::from(USER),
            &sym_key_object,
            sym_key_object.attributes()?,
            &HashSet::new(),
        )
        .await?;

    let initial_date = get_attributes(&kms, &uid, Tag::InitialDate).await?;
    let error = set_attribute(
        &kms,
        &uid,
        Attribute::InitialDate(OffsetDateTime::UNIX_EPOCH),
    )
    .await
    .expect_err("setting InitialDate must fail as read-only");
    assert!(matches!(
        error,
        KmsError::Kmip21Error(ErrorReason::Read_Only_Attribute, _)
    ));
    assert_eq!(
        get_attributes(&kms, &uid, Tag::InitialDate)
            .await?
            .attributes
            .initial_date,
        initial_date.attributes.initial_date
    );

    // Start tests
    //
    let timestamp = 42;
    let offset_datetime = OffsetDateTime::from_unix_timestamp(timestamp).unwrap();
    set_activation_date_and_remove_it(
        &kms,
        &uid,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            current_attribute: Some(Attribute::ActivationDate(offset_datetime)),
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
    set_cryptographic_algorithm_is_rejected_as_read_only(&kms, &uid).await?;
    set_cryptographic_length_is_rejected_as_read_only(&kms, &uid).await?;
    server_managed_attributes_are_rejected(&kms, &uid).await?;
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
    let timestamp = 42;
    let offset_datetime = OffsetDateTime::from_unix_timestamp(timestamp).unwrap();

    set_attribute(kms, uid, Attribute::ActivationDate(offset_datetime)).await?;
    // and check if it is set correctly
    let get_response = get_attributes(kms, uid, Tag::ActivationDate).await?;
    assert_eq!(
        get_response.attributes.activation_date,
        Some(offset_datetime)
    );
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

    let link = Link {
        link_type,
        linked_object_identifier: LinkedObjectIdentifier::TextString("my_link".to_owned()),
    };
    set_attribute(kms, uid, Attribute::Link(link.clone())).await?;

    let get_response = get_attributes(kms, uid, tag).await?;
    assert_eq!(get_response.attributes.link, Some(vec![link]));

    kms.delete_attribute(
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_references: Some(vec![AttributeReference::Standard(tag)]),
            ..DeleteAttribute::default()
        },
        &UserId::from(USER),
    )
    .await?;

    let get_response = get_attributes(kms, uid, tag).await?;
    assert!(get_response.attributes.link.is_none());

    Ok(())
}

/// KMIP 2.1 §4.13: Cryptographic Algorithm is read-only; changing or stripping it would let
/// a key escape the algorithm policy.
async fn set_cryptographic_algorithm_is_rejected_as_read_only(
    kms: &Arc<KMS>,
    uid: &str,
) -> KResult<()> {
    let get_response = get_attributes(kms, uid, Tag::CryptographicAlgorithm).await?;
    assert_eq!(
        get_response.attributes.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );

    let error = set_attribute(
        kms,
        uid,
        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::ChaCha20),
    )
    .await
    .expect_err("setting CryptographicAlgorithm must fail as read-only");
    assert!(matches!(
        error,
        KmsError::Kmip21Error(ErrorReason::Read_Only_Attribute, _)
    ));

    for delete_request in [
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            current_attribute: Some(Attribute::CryptographicAlgorithm(
                CryptographicAlgorithm::AES,
            )),
            attribute_references: None,
        },
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            current_attribute: None,
            attribute_references: Some(vec![AttributeReference::Standard(
                Tag::CryptographicAlgorithm,
            )]),
        },
    ] {
        let error = delete_attribute(kms, delete_request)
            .await
            .expect_err("deleting CryptographicAlgorithm must fail as read-only");
        assert!(matches!(
            error,
            KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _)
        ));
    }

    let get_response = get_attributes(kms, uid, Tag::CryptographicAlgorithm).await?;
    assert_eq!(
        get_response.attributes.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    Ok(())
}

async fn set_cryptographic_length_is_rejected_as_read_only(
    kms: &Arc<KMS>,
    uid: &str,
) -> KResult<()> {
    // The creation request carries a 256-bit length
    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert_eq!(get_response.attributes.cryptographic_length, Some(256));

    let error = set_attribute(kms, uid, Attribute::CryptographicLength(64))
        .await
        .expect_err("setting CryptographicLength must fail as read-only");
    assert!(matches!(
        error,
        KmsError::Kmip21Error(ErrorReason::Read_Only_Attribute, _)
    ));

    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert_eq!(get_response.attributes.cryptographic_length, Some(256));

    let err = delete_attribute(
        kms,
        DeleteAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            current_attribute: Some(Attribute::CryptographicLength(256)),
            attribute_references: None,
        },
    )
    .await
    .expect_err("deleting CryptographicLength must fail as read-only");
    assert!(matches!(
        err,
        KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _)
    ));

    let get_response = get_attributes(kms, uid, Tag::CryptographicLength).await?;
    assert_eq!(get_response.attributes.cryptographic_length, Some(256));
    Ok(())
}

/// Every read-only attribute is refused by all four attribute edits, whether or not the object
/// already holds a value: Add/Set with `Read_Only_Attribute` (KMIP 2.1 §6.1.2.1, §6.1.51.1),
/// Modify/Delete with `Attribute_Read_Only` (§6.1.34.1, §6.1.13.1).
async fn server_managed_attributes_are_rejected(kms: &Arc<KMS>, uid: &str) -> KResult<()> {
    let request = GetAttributes {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        attribute_reference: None,
    };
    let before = kms
        .get_attributes(request.clone(), &UserId::from(USER))
        .await?
        .attributes;
    let user = UserId::from(USER);
    let object = UniqueIdentifier::TextString(uid.to_owned());
    for attribute in [
        Attribute::UniqueIdentifier(UniqueIdentifier::TextString("forged".to_owned())),
        Attribute::ObjectType(ObjectType::Certificate),
        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
        Attribute::CryptographicDomainParameters(CryptographicDomainParameters {
            qlength: None,
            recommended_curve: Some(RecommendedCurve::P256),
        }),
        Attribute::CryptographicLength(64),
        Attribute::CertificateLength(64),
        Attribute::KeyFormatType(KeyFormatType::Raw),
        Attribute::DigitalSignatureAlgorithm(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        Attribute::Digest(Digest {
            hashing_algorithm: HashingAlgorithm::SHA256,
            digest_value: Some(vec![0; 32]),
            key_format_type: None,
        }),
        Attribute::DestroyDate(OffsetDateTime::UNIX_EPOCH),
        Attribute::X509CertificateSubject("CN=forged".to_owned()),
        Attribute::InitialDate(OffsetDateTime::UNIX_EPOCH),
        Attribute::LastChangeDate(OffsetDateTime::UNIX_EPOCH),
        Attribute::OriginalCreationDate(OffsetDateTime::UNIX_EPOCH),
        Attribute::Fresh(true),
    ] {
        let results = [
            (
                kms.add_attribute(
                    AddAttribute {
                        unique_identifier: object.clone(),
                        new_attribute: attribute.clone(),
                    },
                    &user,
                )
                .await
                .err(),
                ErrorReason::Read_Only_Attribute,
            ),
            (
                set_attribute(kms, uid, attribute.clone()).await.err(),
                ErrorReason::Read_Only_Attribute,
            ),
            (
                kms.modify_attribute(
                    ModifyAttribute {
                        unique_identifier: Some(object.clone()),
                        new_attribute: attribute.clone(),
                    },
                    &user,
                )
                .await
                .err(),
                ErrorReason::Attribute_Read_Only,
            ),
            (
                delete_attribute(
                    kms,
                    DeleteAttribute {
                        unique_identifier: Some(object.clone()),
                        current_attribute: Some(attribute.clone()),
                        attribute_references: None,
                    },
                )
                .await
                .err(),
                ErrorReason::Attribute_Read_Only,
            ),
        ];
        for (error, expected) in results {
            assert!(
                matches!(&error, Some(KmsError::Kmip21Error(reason, _)) if *reason == expected),
                "{attribute}: {error:?}"
            );
        }
    }
    let after = kms
        .get_attributes(request, &UserId::from(USER))
        .await?
        .attributes;
    assert_eq!(after, before);
    Ok(())
}

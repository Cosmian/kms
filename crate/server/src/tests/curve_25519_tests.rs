use std::sync::Arc;

use cloudproof::reexport::crypto_core::X25519_PUBLIC_KEY_LENGTH;
use cosmian_kmip::{
    crypto::elliptic_curves::{
        kmip_requests::{
            create_ec_key_pair_request, get_private_key_request, get_public_key_request,
        },
        operation::to_ec_public_key,
        CURVE_25519_Q_LENGTH_BITS,
    },
    kmip::{
        extra::tagging::EMPTY_TAGS,
        kmip_messages::{Message, MessageBatchItem, MessageHeader},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, Import, Operation},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, LinkType,
            LinkedObjectIdentifier, ProtocolVersion, RecommendedCurve, ResultStatusEnumeration,
            UniqueIdentifier,
        },
    },
};

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::{KResult, KResultHelper},
    tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_curve_25519_key_pair() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = create_ec_key_pair_request(
        Some(UniqueIdentifier::TextString("ec_sk_uid".to_owned())),
        EMPTY_TAGS,
        RecommendedCurve::CURVE25519,
        false,
    )?;
    let response = kms.create_key_pair(request, owner, None).await?;
    // check that the private and public key exist
    // check secret key
    let sk_response = kms
        .get(
            get_private_key_request(
                response
                    .private_key_unique_identifier
                    .as_str()
                    .context("no string for the private_key_unique_identifier")?,
            ),
            owner,
            None,
        )
        .await?;
    let sk_uid = sk_response
        .unique_identifier
        .as_str()
        .context("no string for the unique_identifier")?;
    assert_eq!(sk_uid, "ec_sk_uid".to_owned());
    let sk = &sk_response.object;
    let sk_key_block = match sk {
        Object::PrivateKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Private Key".to_owned(),
            ))
        }
    };
    assert_eq!(
        sk_key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ECDH),
    );
    assert_eq!(
        sk_key_block.cryptographic_length,
        Some(CURVE_25519_Q_LENGTH_BITS)
    );
    assert_eq!(
        sk_key_block.key_format_type,
        KeyFormatType::TransparentECPrivateKey
    );
    // check link to public key
    let attributes = sk_key_block.key_value.attributes()?;
    assert_eq!(
        attributes
            .link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
            .len(),
        1
    );
    let link = &attributes
        .link
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?[0];
    assert_eq!(link.link_type, LinkType::PublicKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.public_key_unique_identifier.to_string())
    );

    // check public key
    let pk_response = kms
        .get(
            get_public_key_request(
                response
                    .public_key_unique_identifier
                    .as_str()
                    .context("no string for the public_key_unique_identifier")?,
            ),
            owner,
            None,
        )
        .await?;
    let pk = &pk_response.object;
    let pk_key_block = match &pk {
        Object::PublicKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Public Key".to_owned(),
            ))
        }
    };
    assert_eq!(
        pk_key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ECDH),
    );
    assert_eq!(
        pk_key_block.cryptographic_length,
        Some(CURVE_25519_Q_LENGTH_BITS)
    );
    assert_eq!(
        pk_key_block.key_format_type,
        KeyFormatType::TransparentECPublicKey
    );
    // check link to secret key
    let attributes = pk_key_block.key_value.attributes()?;
    assert_eq!(
        attributes
            .link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
            .len(),
        1
    );
    let link = &attributes
        .link
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?[0];
    assert_eq!(link.link_type, LinkType::PrivateKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.private_key_unique_identifier.to_string())
    );
    // test import of public key
    let pk_bytes = pk.key_block()?.key_bytes()?;
    assert_eq!(pk_bytes.len(), X25519_PUBLIC_KEY_LENGTH);
    let pk = to_ec_public_key(
        &pk_bytes,
        u32::try_from(CURVE_25519_Q_LENGTH_BITS)?,
        sk_uid,
        RecommendedCurve::CURVE25519,
        Some(CryptographicAlgorithm::ECDH),
        Some(CryptographicUsageMask::Unrestricted),
    )?;
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::PublicKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
        object: pk.clone(),
    };
    let new_uid = kms.import(request, owner, None).await?.unique_identifier;
    // update
    let request = Import {
        unique_identifier: new_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
        object: pk,
    };
    let update_response = kms.import(request, owner, None).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}

#[tokio::test]
async fn test_curve_25519_multiple() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 2,
            ..Default::default()
        },
        items: vec![
            MessageBatchItem::new(Operation::CreateKeyPair(create_ec_key_pair_request(
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVE25519,
                false,
            )?)),
            MessageBatchItem::new(Operation::Locate(
                cosmian_kmip::kmip::kmip_operations::Locate::default(),
            )),
        ],
    };

    let response = kms.message(request, owner, None).await?;
    assert_eq!(response.header.batch_count, 2);

    let request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            batch_count: 4,
            ..Default::default()
        },
        items: vec![
            MessageBatchItem::new(Operation::CreateKeyPair(create_ec_key_pair_request(
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVE25519,
                false,
            )?)),
            MessageBatchItem::new(Operation::CreateKeyPair(create_ec_key_pair_request(
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVEED25519,
                false,
            )?)),
            MessageBatchItem::new(Operation::CreateKeyPair(create_ec_key_pair_request(
                None,
                EMPTY_TAGS,
                RecommendedCurve::SECP256K1,
                false,
            )?)),
            MessageBatchItem::new(Operation::CreateKeyPair(create_ec_key_pair_request(
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVEED25519,
                false,
            )?)),
        ],
    };

    let response = kms.message(request, owner, None).await?;
    assert_eq!(response.header.batch_count, 4);
    assert_eq!(response.items.len(), 4);

    assert_eq!(
        response.items[0].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[0].response_payload else {
        panic!("not a create key pair response payload");
    };

    // Should fail in fips mode since ed25519 for ECDH is not allowed.
    #[cfg(feature = "fips")]
    assert_eq!(
        response.items[1].result_status,
        ResultStatusEnumeration::OperationFailed
    );
    #[cfg(not(feature = "fips"))]
    assert_eq!(
        response.items[1].result_status,
        ResultStatusEnumeration::Success
    );

    #[cfg(not(feature = "fips"))]
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[1].response_payload else {
        panic!("not a create key pair response payload");
    };

    assert!(response.items[2].response_payload.is_none());
    assert_eq!(
        response.items[2].result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        response.items[2].result_reason,
        Some(ErrorReason::Operation_Not_Supported)
    );
    assert_eq!(
        response.items[2].result_message,
        Some(
            "Not Supported: Generation of Key Pair for curve: SECP256K1, is not supported"
                .to_owned()
        )
    );

    // Should fail in fips mode since ed25519 for ECDH is not allowed.
    #[cfg(feature = "fips")]
    assert_eq!(
        response.items[3].result_status,
        ResultStatusEnumeration::OperationFailed
    );
    #[cfg(not(feature = "fips"))]
    assert_eq!(
        response.items[3].result_status,
        ResultStatusEnumeration::Success
    );

    #[cfg(not(feature = "fips"))]
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[3].response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}

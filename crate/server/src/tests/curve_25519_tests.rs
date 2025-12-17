#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                ResponseMessageBatchItemVersioned,
            },
            kmip_types::{
                CryptographicUsageMask, ErrorReason, ProtocolVersion, ResultStatusEnumeration,
            },
        },
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS,
            kmip_attributes::Attributes,
            kmip_messages::RequestMessageBatchItem,
            kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
            kmip_operations::{Import, Operation},
            kmip_types::{
                CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
                RecommendedCurve, UniqueIdentifier,
            },
            requests::{
                create_ec_key_pair_request, get_ec_private_key_request, get_ec_public_key_request,
            },
        },
    },
    cosmian_kms_crypto::{
        crypto::elliptic_curves::{CURVE_25519_Q_LENGTH_BITS, operation::to_ec_public_key},
        reexport::cosmian_crypto_core::X25519_PUBLIC_KEY_LENGTH,
    },
};
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::{KResult, KResultHelper},
    tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_curve_25519() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = Uuid::new_v4().to_string();

    // request key pair creation
    let request = create_ec_key_pair_request(
        Some(UniqueIdentifier::TextString("ec_sk_uid".to_owned())),
        EMPTY_TAGS,
        RecommendedCurve::CURVE25519,
        false,
        None,
    )?;
    let response = kms.create_key_pair(request, &owner, None).await?;
    // check that the private and public keys exist
    // check secret key
    let sk_response = kms
        .get(
            get_ec_private_key_request(
                response
                    .private_key_unique_identifier
                    .as_str()
                    .context("no string for the private_key_unique_identifier")?,
            ),
            &owner,
        )
        .await?;
    let sk_uid = sk_response
        .unique_identifier
        .as_str()
        .context("no string for the unique_identifier")?;
    assert_eq!(sk_uid, "ec_sk_uid".to_owned());
    let sk = &sk_response.object;
    let sk_key_block = match sk {
        Object::PrivateKey(PrivateKey { key_block }) => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Private Key".to_owned(),
            ));
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
    let attributes = sk_key_block.attributes()?;
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
    assert!(
        link.linked_object_identifier
            == LinkedObjectIdentifier::TextString(
                response.public_key_unique_identifier.to_string()
            )
    );

    // check public key
    let pk_response = kms
        .get(
            get_ec_public_key_request(
                response
                    .public_key_unique_identifier
                    .as_str()
                    .context("no string for the public_key_unique_identifier")?,
            ),
            &owner,
        )
        .await?;
    let pk = &pk_response.object;
    let pk_key_block = match &pk {
        Object::PublicKey(PublicKey { key_block }) => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Public Key".to_owned(),
            ));
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
    let attributes = pk_key_block.attributes()?;
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
    assert!(
        link.linked_object_identifier
            == LinkedObjectIdentifier::TextString(
                response.private_key_unique_identifier.to_string()
            )
    );
    // test import of public key
    let pk_bytes = pk.key_block()?.ec_raw_bytes()?;
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
    let new_uid = kms.import(request, &owner, None).await?.unique_identifier;
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
    let update_response = kms.import(request, &owner, None).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}

#[tokio::test]
async fn test_curve_25519_multiple() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = Uuid::new_v4().to_string();

    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 2,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::CURVE25519,
                    false,
                    None,
                )?)),
            )),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Locate(
                Box::default(),
            ))),
        ],
    };

    let response = kms.message(request, &owner).await?;
    assert_eq!(response.response_header.batch_count, 2);

    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 4,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::CURVE25519,
                    false,
                    None,
                )?)),
            )),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::CURVEED25519,
                    false,
                    None,
                )?)),
            )),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::SECT113R1,
                    false,
                    None,
                )?)),
            )),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::CURVEED25519,
                    false,
                    None,
                )?)),
            )),
        ],
    };

    let response = kms.message(request, &owner).await?;
    assert_eq!(response.response_header.batch_count, 4);
    assert_eq!(response.batch_item.len(), 4);

    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("not a v2.1 response");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::CreateKeyPairResponse(_)) = &batch_item.response_payload else {
        panic!("not a create key pair response payload");
    };

    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[1] else {
        panic!("not a v2.1 response");
    };

    // Should fail in fips mode since ed25519 for ECDH is not allowed.
    #[cfg(not(feature = "non-fips"))]
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    #[cfg(feature = "non-fips")]
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    #[cfg(feature = "non-fips")]
    let Some(Operation::CreateKeyPairResponse(_)) = &batch_item.response_payload else {
        panic!("not a create key pair response payload");
    };

    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[2] else {
        panic!("not a v2.1 response");
    };

    assert!(batch_item.response_payload.is_none());
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        batch_item.result_reason,
        Some(ErrorReason::Operation_Not_Supported)
    );
    assert_eq!(
        batch_item.result_message,
        Some(
            "Not Supported: Generation of Key Pair for curve: SECT113R1, is not supported"
                .to_owned()
        )
    );

    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[3] else {
        panic!("not a v2.1 response");
    };

    // Should fail in fips mode since ed25519 for ECDH is not allowed.
    #[cfg(not(feature = "non-fips"))]
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    #[cfg(feature = "non-fips")]
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    #[cfg(feature = "non-fips")]
    let Some(Operation::CreateKeyPairResponse(_)) = &batch_item.response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}

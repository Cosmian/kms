use std::sync::Arc;

use cosmian_crypto_core::X25519_PUBLIC_KEY_LENGTH;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
        RecommendedCurve,
    },
};
use cosmian_kms_utils::crypto::curve_25519::{
    kmip_requests::{ec_create_key_pair_request, get_private_key_request, get_public_key_request},
    operation::{self, to_curve_25519_256_public_key},
};

use crate::{
    config::ServerParams, error::KmsError, result::KResult, tests::test_utils::https_clap_config,
    KMSServer,
};

#[actix_rt::test]
async fn test_curve_25519_key_pair() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(&clap_config).await?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = ec_create_key_pair_request(&[] as &[&str], RecommendedCurve::CURVE25519)?;
    let response = kms.create_key_pair(request, owner, None).await?;
    // check that the private and public key exist
    // check secret key
    let sk_response = kms
        .get(
            get_private_key_request(&response.private_key_unique_identifier),
            owner,
            None,
        )
        .await?;
    let sk_uid = &sk_response.unique_identifier;
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
        CryptographicAlgorithm::ECDH,
    );
    assert_eq!(sk_key_block.cryptographic_length, operation::Q_LENGTH_BITS,);
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
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?
            .len(),
        1
    );
    let link = &attributes
        .link
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?[0];
    assert_eq!(link.link_type, LinkType::PublicKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.public_key_unique_identifier.clone())
    );

    // check public key
    let pk_response = kms
        .get(
            get_public_key_request(&response.public_key_unique_identifier),
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
        CryptographicAlgorithm::ECDH,
    );
    assert_eq!(pk_key_block.cryptographic_length, operation::Q_LENGTH_BITS,);
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
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?
            .len(),
        1
    );
    let link = &attributes
        .link
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?[0];
    assert_eq!(link.link_type, LinkType::PrivateKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.private_key_unique_identifier)
    );
    // test import of public key
    let pk_bytes = pk.key_block()?.key_bytes()?;
    assert_eq!(pk_bytes.len(), X25519_PUBLIC_KEY_LENGTH);
    let pk = to_curve_25519_256_public_key(&pk_bytes, sk_uid);
    let request = Import {
        unique_identifier: String::new(),
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

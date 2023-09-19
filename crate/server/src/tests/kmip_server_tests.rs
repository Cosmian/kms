use std::sync::Arc;

use cloudproof::reexport::crypto_core::X25519_PUBLIC_KEY_LENGTH;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, KeyWrapType, LinkType,
        LinkedObjectIdentifier, RecommendedCurve, WrappingMethod,
    },
};
use cosmian_kms_utils::crypto::curve_25519::{
    kmip_requests::{ec_create_key_pair_request, get_private_key_request, get_public_key_request},
    operation::{to_curve_25519_256_public_key, Q_LENGTH_BITS},
};
use cosmian_logger::log_utils::log_init;
use tracing::trace;
use uuid::Uuid;

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
    assert_eq!(sk_key_block.cryptographic_length, Q_LENGTH_BITS,);
    assert_eq!(
        sk_key_block.key_format_type,
        KeyFormatType::TransparentECPrivateKey
    );
    //check link to public key
    let attr = sk_key_block.key_value.attributes()?;
    assert_eq!(
        attr.link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?
            .len(),
        1
    );
    let link = &attr
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
    assert_eq!(pk_key_block.cryptographic_length, Q_LENGTH_BITS,);
    assert_eq!(
        pk_key_block.key_format_type,
        KeyFormatType::TransparentECPublicKey
    );
    // check link to secret key
    let attr = pk_key_block.key_value.attributes()?;
    assert_eq!(
        attr.link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?
            .len(),
        1
    );
    let link = &attr
        .link
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("links should not be empty".to_string()))?[0];
    assert_eq!(link.link_type, LinkType::PrivateKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.private_key_unique_identifier)
    );
    // test import of public key
    let pk_bytes = pk_key_block.key_bytes()?;
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
        key_wrapping_data: None,
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
        key_wrapping_data: None,
    };
    let update_response = kms.import(request, owner, None).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}

#[actix_rt::test]
async fn test_import_wrapped_symmetric_key() -> KResult<()> {
    // log_init("info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(&clap_config).await?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let wrapped_symmetric_key = [0_u8; 32];
    let aesgcm_nonce = [0_u8; 12];

    let key_material = KeyMaterial::ByteString(wrapped_symmetric_key.to_vec());

    let symmetric_key = Object::SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material,
                attributes: None,
            },
            cryptographic_algorithm: CryptographicAlgorithm::AES,
            cryptographic_length: wrapped_symmetric_key.len() as i32,
            key_wrapping_data: Some(KeyWrappingData {
                wrapping_method: WrappingMethod::Encrypt,
                iv_counter_nonce: Some(aesgcm_nonce.to_vec()),
                ..KeyWrappingData::default()
            }),
        },
    };

    let uid = Uuid::new_v4().to_string();

    let request = Import {
        unique_identifier: uid,
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: Some(KeyWrapType::AsRegistered),
        attributes: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(wrapped_symmetric_key.len() as i32),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::default()
        },
        object: symmetric_key,
        key_wrapping_data: None,
    };

    trace!("request: {:?}", request);
    let response = kms.import(request, owner, None).await?;
    trace!("response: {:?}", response);

    Ok(())
}

#[actix_rt::test]
async fn test_database_user_tenant() -> KResult<()> {
    log_init("info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(&clap_config).await?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = ec_create_key_pair_request(&[] as &[&str], RecommendedCurve::CURVE25519)?;
    let response = kms.create_key_pair(request, owner, None).await?;

    // check that we can get the private and public key
    // check secret key
    kms.get(
        get_private_key_request(&response.private_key_unique_identifier),
        owner,
        None,
    )
    .await?;

    // check public key
    kms.get(
        get_public_key_request(&response.public_key_unique_identifier),
        owner,
        None,
    )
    .await?;

    // request with an invalid `owner` but with the same `uid` and assert we don't get any key
    let owner = "invalid_owner";
    // check public key
    let sk_response = kms
        .get(
            get_private_key_request(&response.private_key_unique_identifier),
            owner,
            None,
        )
        .await;
    assert!(sk_response.is_err());

    let pk_response = kms
        .get(
            get_public_key_request(&response.public_key_unique_identifier),
            owner,
            None,
        )
        .await;
    assert!(pk_response.is_err());

    Ok(())
}

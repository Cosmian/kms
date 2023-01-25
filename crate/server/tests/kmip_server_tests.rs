use std::sync::Arc;

use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, KeyWrapType, LinkType,
        LinkedObjectIdentifier, WrappingMethod,
    },
};
use cosmian_kms_server::{
    config::{auth::AuthConfig, init_config, Config},
    core::crud::KmipServer,
    error::KmsError,
    log_utils::log_init,
    result::KResult,
    KMSServer,
};
use cosmian_kms_utils::crypto::curve_25519;
use tracing::trace;
use uuid::Uuid;

#[actix_rt::test]
async fn test_curve_25519_key_pair() -> KResult<()> {
    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "console-dev.eu.auth0.com".to_string(),
        },
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = curve_25519::kmip_requests::create_key_pair_request();
    let response = kms.create_key_pair(request, owner, None).await?;
    // check that the private and public key exist
    // check secret key
    let sk_response = kms
        .get(
            curve_25519::kmip_requests::get_private_key_request(
                &response.private_key_unique_identifier,
            ),
            owner,
            None,
        )
        .await?;
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
        CryptographicAlgorithm::EC,
    );
    assert_eq!(
        sk_key_block.cryptographic_length,
        curve_25519::operation::Q_LENGTH_BITS,
    );
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
            curve_25519::kmip_requests::get_public_key_request(
                &response.public_key_unique_identifier,
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
        CryptographicAlgorithm::EC,
    );
    assert_eq!(
        pk_key_block.cryptographic_length,
        curve_25519::operation::Q_LENGTH_BITS,
    );
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
    let pk_bytes = curve_25519::kmip_requests::extract_key_bytes(pk)?;
    let pk = curve_25519::kmip_requests::parse_public_key(&pk_bytes)?;
    let request = Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::PublicKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let new_uid = kms.import(request, owner, None).await?.unique_identifier;
    // update

    let pk = curve_25519::kmip_requests::parse_public_key(&pk_bytes)?;
    let request = Import {
        unique_identifier: new_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let update_response = kms.import(request, owner, None).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}

#[actix_rt::test]
async fn test_import_wrapped_symmetric_key() -> KResult<()> {
    log_init("info");

    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "console-dev.eu.auth0.com".to_string(),
        },
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
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
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(wrapped_symmetric_key.len() as i32),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: ObjectType::SymmetricKey,
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        object: symmetric_key,
    };

    trace!("request: {:?}", request);
    let response = kms.import(request, owner, None).await?;
    trace!("response: {:?}", response);

    Ok(())
}

#[actix_rt::test]
async fn test_database_user_tenant() -> KResult<()> {
    log_init("info");

    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "console-dev.eu.auth0.com".to_string(),
        },
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = curve_25519::kmip_requests::create_key_pair_request();
    let response = kms.create_key_pair(request, owner, None).await?;

    // check that we can get the private and public key
    // check secret key
    kms.get(
        curve_25519::kmip_requests::get_private_key_request(
            &response.private_key_unique_identifier,
        ),
        owner,
        None,
    )
    .await?;

    // check public key
    kms.get(
        curve_25519::kmip_requests::get_public_key_request(&response.public_key_unique_identifier),
        owner,
        None,
    )
    .await?;

    // request with an invalid `owner` but with the same `uid` and assert we don't get any key
    let owner = "invalid_owner";
    // check public key
    let sk_response = kms
        .get(
            curve_25519::kmip_requests::get_private_key_request(
                &response.private_key_unique_identifier,
            ),
            owner,
            None,
        )
        .await;
    assert!(sk_response.is_err());

    let pk_response = kms
        .get(
            curve_25519::kmip_requests::get_public_key_request(
                &response.public_key_unique_identifier,
            ),
            owner,
            None,
        )
        .await;
    assert!(pk_response.is_err());

    Ok(())
}

#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, KeyWrapType},
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyValue, KeyWrappingData},
            kmip_objects::{Object, ObjectType, PrivateKey, PublicKey, SymmetricKey},
            kmip_operations::{Get, Import, Register},
            kmip_types::{
                CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
                RecommendedCurve, UniqueIdentifier, WrappingMethod,
            },
            requests::{
                create_ec_key_pair_request, create_symmetric_key_kmip_object,
                get_ec_private_key_request, get_ec_public_key_request,
                symmetric_key_create_request,
            },
        },
    },
    cosmian_kms_crypto::{
        crypto::{CURVE_25519_Q_LENGTH_BITS, elliptic_curves::operation::to_ec_public_key},
        reexport::cosmian_crypto_core::X25519_PUBLIC_KEY_LENGTH,
    },
};
use cosmian_logger::trace;
use uuid::Uuid;
use zeroize::Zeroizing;

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

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request =
        create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519, false, None)?;
    let response = kms.create_key_pair(request, owner, None).await?;
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
            owner,
        )
        .await?;
    let sk_uid = sk_response
        .unique_identifier
        .as_str()
        .context("no string for the unique_identifier")?;
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
    // check the link to a public key
    let attr = sk_key_block.attributes()?;
    assert_eq!(
        attr.link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
            .len(),
        1
    );
    let link = &attr
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
            owner,
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
    let attr = pk_key_block.attributes()?;
    assert_eq!(
        attr.link
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
            .len(),
        1
    );
    let link = &attr
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
    let pk_bytes = pk_key_block.ec_raw_bytes()?;
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
async fn test_import_wrapped_symmetric_key() -> KResult<()> {
    cosmian_logger::log_init(None);

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let wrapped_symmetric_key = [0_u8; 32];
    let aesgcm_nonce = [0_u8; 12];

    let symmetric_key = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::ByteString(Zeroizing::from(
                wrapped_symmetric_key.to_vec(),
            ))),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(i32::try_from(wrapped_symmetric_key.len())? * 8),
            key_wrapping_data: Some(KeyWrappingData {
                wrapping_method: WrappingMethod::Encrypt,
                iv_counter_nonce: Some(aesgcm_nonce.to_vec()),
                ..KeyWrappingData::default()
            }),
        },
    });

    let uid = Uuid::new_v4().to_string();

    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(uid),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: Some(KeyWrapType::AsRegistered),
        attributes: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(i32::try_from(wrapped_symmetric_key.len())?),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::default()
        },
        object: symmetric_key,
    };

    trace!("request: {}", request);
    let response = kms.import(request, owner, None).await?;
    trace!("response: {}", response);

    Ok(())
}

#[tokio::test]
async fn test_create_transparent_symmetric_key() -> KResult<()> {
    cosmian_logger::log_init(None);

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let request = symmetric_key_create_request(
        Some(UniqueIdentifier::TextString("sym_key_id".to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;

    trace!("request: {}", request);
    let response = kms.create(request, owner, None).await?;
    trace!("response: {}", response);

    // Get symmetric key without specifying key format type
    //
    let request = Get::new(response.unique_identifier, false, None, None);
    let response = kms.get(request, owner).await?;
    assert_eq!(
        KeyFormatType::Raw,
        response.object.key_block()?.key_format_type
    );
    // Check key UID has been setup
    assert_eq!(
        "sym_key_id".to_owned(),
        response
            .unique_identifier
            .as_str()
            .context("no string for the unique_identifier")?
    );

    // Get symmetric key specifying key format type
    //
    let request = Get::new(
        response.unique_identifier,
        false,
        None,
        Some(KeyFormatType::TransparentSymmetricKey),
    );
    let response = kms.get(request, owner).await?;
    assert_eq!(
        KeyFormatType::TransparentSymmetricKey,
        response.object.key_block()?.key_format_type
    );

    Ok(())
}

#[tokio::test]
async fn test_database_user_tenant() -> KResult<()> {
    cosmian_logger::log_init(None);

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request =
        create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519, false, None)?;
    let response = kms.create_key_pair(request, owner, None).await?;

    // check that we can get the private and public key
    // check secret key
    kms.get(
        get_ec_private_key_request(
            response
                .private_key_unique_identifier
                .as_str()
                .context("no string for the private_key_unique_identifier")?,
        ),
        owner,
    )
    .await?;

    // check public key
    kms.get(
        get_ec_public_key_request(
            response
                .public_key_unique_identifier
                .as_str()
                .context("no string for the public_key_unique_identifier")?,
        ),
        owner,
    )
    .await?;

    // request with an invalid `owner` but with the same `uid` and assert we don't get any key
    let owner = "invalid_owner";
    // check public key
    let sk_response = kms
        .get(
            get_ec_private_key_request(
                response
                    .private_key_unique_identifier
                    .as_str()
                    .context("no string for the private_key_unique_identifier")?,
            ),
            owner,
        )
        .await;
    sk_response.unwrap_err();

    let pk_response = kms
        .get(
            get_ec_public_key_request(
                response
                    .public_key_unique_identifier
                    .as_str()
                    .context("no string for the public_key_unique_identifier")?,
            ),
            owner,
        )
        .await;
    pk_response.unwrap_err();

    Ok(())
}

#[tokio::test]
async fn test_register_operation() -> KResult<()> {
    cosmian_logger::log_init(None);

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let sym_key = create_symmetric_key_kmip_object(
        &[1, 2, 3, 4],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20),
            ..Default::default()
        },
    )?;

    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        sensitive: Some(false),
        ..Attributes::default()
    };

    let request = Register {
        object_type: ObjectType::SymmetricKey,
        attributes: attributes.clone(),
        object: sym_key,
        protection_storage_masks: None,
    };

    trace!("request: {}", request);
    let register_response = kms.register(request, owner, None).await?;
    trace!("response: {}", register_response);

    let uid = register_response.unique_identifier;
    if let UniqueIdentifier::TextString(s) = &uid {
        assert!(
            !s.is_empty(),
            "Unique Identifier (TextString) should not be empty"
        );
    } else {
        panic!("Expected UID to be a TextString");
    }

    let get_request = Get::new(uid.clone(), false, None, None);
    let get_response = kms.get(get_request, owner).await?;
    let key_block: &KeyBlock = get_response.object.key_block()?;

    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);

    let retrieved_attributes = get_response.object.attributes()?;
    // The CryptographicAlgorithm (and other attributes) should be taken from the request's `attributes` field,
    // not from any embedded metadata within the object itself.
    assert_eq!(
        retrieved_attributes.cryptographic_algorithm,
        attributes.cryptographic_algorithm
    );
    assert_eq!(
        retrieved_attributes.cryptographic_length,
        attributes.cryptographic_length
    );
    assert_eq!(
        retrieved_attributes.cryptographic_usage_mask,
        attributes.cryptographic_usage_mask
    );
    assert_eq!(retrieved_attributes.object_type, attributes.object_type);

    Ok(())
}

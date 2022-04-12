use std::{convert::TryFrom, sync::Arc};

use cosmian_kmip::kmip::{
    access::ObjectOperationTypes,
    kmip_data_structures::{KeyBlock, KeyValue, KeyWrappingData},
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, KeyFormatType, KeyWrapType,
        LinkType, LinkedObjectIdentifier, StateEnumeration, WrappingMethod,
    },
};
use cosmian_kms_utils::crypto::{curve_25519, mcfe::operation::secret_key_from_lwe_secret_key};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;
use tempfile::tempdir;
use tracing::trace;
use uuid::Uuid;

use crate::{
    config::init_config,
    error::KmsError,
    kmip::kmip_server::{
        database::Database, server::kmip_server::KmipServer, sqlite::SqlitePool, KMSServer,
    },
    log_utils::log_init,
    result::KResult,
};

#[actix_rt::test]
async fn test_crud() -> KResult<()> {
    log_init("info");
    let owner = "eyJhbGciOiJSUzI1Ni";
    let dir = tempdir()?;
    let file_path = dir.path().join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }

    let lwe_setup = lwe::Setup {
        clients: 10,
        message_length: 31,
        message_bound: BigUint::from(std::u32::MAX),
        vectors_bound: BigUint::from(std::u32::MAX),
        n0: 1024,
    };
    let lwe_sk = lwe::SecretKey::try_from(&lwe_setup)?;
    let sk = secret_key_from_lwe_secret_key(&lwe_setup, &lwe_sk)?;
    //
    let db = SqlitePool::instantiate(&file_path).await?;
    //
    let uid = db.create(None, owner, &sk).await?;
    //
    let list = db.list(owner).await?;
    assert_eq!(1, list.len());
    assert_eq!(uid, list[0].0);
    //
    let req_obj = db.retrieve(&uid, owner, ObjectOperationTypes::Get).await?;
    assert!(req_obj.is_some());
    let req_sk =
        req_obj.ok_or_else(|| KmsError::ServerError("invalid object returned".to_owned()))?;
    assert_eq!(&sk, &req_sk.0);
    // check attributes
    let key_block = match &sk {
        Object::SymmetricKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Symmetric Key".to_owned(),
            ))
        }
    };
    let (key_material, attributes) = key_block
        .key_value
        .plaintext()
        .ok_or_else(|| KmsError::ServerError("invalid Plain Text Key Value created".to_owned()))?;
    let attributes = attributes
        .as_ref()
        .expect("attributes should have been created");

    let req_key_block = match &req_sk.0 {
        Object::SymmetricKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Symmetric Key".to_owned(),
            ))
        }
    };
    let req_attr = req_key_block.key_value.attributes()?;
    assert_eq!(
        &attributes.cryptographic_algorithm.unwrap(),
        &req_attr.cryptographic_algorithm.unwrap()
    );
    assert_eq!(
        &attributes.cryptographic_parameters,
        &req_attr.cryptographic_parameters
    );

    //update
    let mut updated_key_block = key_block.clone();
    let update_attr = Attributes {
        cryptographic_parameters: Some(CryptographicParameters {
            invocation_field_length: Some(42u64),
            ..(req_attr.cryptographic_parameters).clone().unwrap()
        }),
        ..attributes.clone()
    };
    updated_key_block.key_value = KeyValue::PlainText {
        key_material: key_material.clone(),
        attributes: Some(update_attr),
    };
    db.update_object(
        &uid,
        owner,
        &Object::SymmetricKey {
            key_block: updated_key_block,
        },
    )
    .await?;

    // check update
    let sk2 = db
        .retrieve(&uid, owner, ObjectOperationTypes::Get)
        .await?
        .unwrap();
    let req_key_block_2 = match &sk2.0 {
        Object::SymmetricKey { key_block } => key_block,
        _other => return Err(KmsError::ServerError("invalid object returned".to_owned())),
    };
    let req_attr_2 = req_key_block_2.key_value.attributes()?;
    assert_eq!(
        &42u64,
        req_attr_2
            .cryptographic_parameters
            .as_ref()
            .unwrap()
            .invocation_field_length
            .as_ref()
            .unwrap()
    );

    // upsert
    let uid_upsert = Uuid::new_v4().to_string();
    db.upsert(&uid_upsert, owner, &sk, StateEnumeration::Active)
        .await?;
    db.upsert(&uid_upsert, owner, &sk2.0, StateEnumeration::Active)
        .await?;
    let sk2_ = db
        .retrieve(&uid, owner, ObjectOperationTypes::Get)
        .await?
        .unwrap();
    assert_eq!(&sk2, &sk2_);

    // delete and list
    assert_eq!(2, db.list(owner).await?.len());
    db.delete(&uid, owner).await?;
    assert_eq!(1, db.list(owner).await?.len());
    db.delete(&uid_upsert, owner).await?;
    assert_eq!(0, db.list(owner).await?.len());
    //cleanup
    dir.close()?;
    Ok(())
}

#[actix_rt::test]
async fn test_crud_2() -> KResult<()> {
    log_init("debug");
    let owner = "eyJhbGciOiJSUzI1Ni";
    let dir = tempdir()?;
    let file_path = dir.path().join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    let lwe_setup = lwe::Setup {
        clients: 10,
        message_length: 31,
        message_bound: BigUint::from(std::u32::MAX),
        vectors_bound: BigUint::from(std::u32::MAX),
        n0: 1024,
    };
    let lwe_sk = lwe::SecretKey::try_from(&lwe_setup)?;
    let sk = secret_key_from_lwe_secret_key(&lwe_setup, &lwe_sk)?;
    //
    let db = SqlitePool::instantiate(&file_path).await?;
    //
    let uid = db.create(None, owner, &sk).await?;
    //
    let list = db.list(owner).await?;
    assert_eq!(1, list.len());
    assert_eq!(uid, list[0].0);
    //
    let req_obj = db.retrieve(&uid, owner, ObjectOperationTypes::Get).await?;
    assert!(req_obj.is_some());
    let (req_sk, _state) =
        req_obj.ok_or_else(|| KmsError::ServerError("invalid object returned".to_owned()))?;
    assert_eq!(&sk, &req_sk);
    // check attributes
    let key_block = match &sk {
        Object::SymmetricKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Symmetric Key".to_owned(),
            ))
        }
    };
    let (key_material, attributes) = match &key_block.key_value {
        KeyValue::PlainText {
            key_material,
            attributes,
            ..
        } => (key_material, attributes),
        _other => {
            return Err(KmsError::ServerError(
                "invalid Plain Text Key Value created".to_owned(),
            ))
        }
    };
    let attributes = attributes
        .as_ref()
        .expect("attributes should have been created");

    let req_key_block = match &req_sk {
        Object::SymmetricKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Symmetric Key".to_owned(),
            ))
        }
    };
    let req_attr = match &req_key_block.key_value {
        KeyValue::PlainText { attributes, .. } => attributes
            .as_ref()
            .expect("attributes should have been recovered"),
        _other => {
            return Err(KmsError::ServerError(
                "invalid Key Value returned".to_owned(),
            ))
        }
    };
    assert_eq!(
        &attributes.cryptographic_algorithm.unwrap(),
        &req_attr.cryptographic_algorithm.unwrap()
    );
    assert_eq!(
        &attributes.cryptographic_parameters,
        &req_attr.cryptographic_parameters
    );

    // update
    let mut updated_key_block = key_block.clone();
    let update_attr = Attributes {
        cryptographic_parameters: Some(CryptographicParameters {
            invocation_field_length: Some(42u64),
            ..(req_attr.cryptographic_parameters).clone().unwrap()
        }),
        ..attributes.clone()
    };
    updated_key_block.key_value = KeyValue::PlainText {
        key_material: key_material.clone(),
        attributes: Some(update_attr),
    };
    db.update_object(
        &uid,
        owner,
        &Object::SymmetricKey {
            key_block: updated_key_block,
        },
    )
    .await?;

    // check update
    let (sk2, _state) = db
        .retrieve(&uid, owner, ObjectOperationTypes::Get)
        .await?
        .unwrap();
    let req_key_block_2 = match &sk2 {
        Object::SymmetricKey { key_block } => key_block,
        _other => return Err(KmsError::ServerError("invalid object returned".to_owned())),
    };
    let req_attr_2 = match &req_key_block_2.key_value {
        KeyValue::PlainText { attributes, .. } => attributes
            .as_ref()
            .expect("attributes should have been recovered"),
        _other => {
            return Err(KmsError::ServerError(
                "invalid Key Value returned".to_owned(),
            ))
        }
    };
    assert_eq!(
        &42u64,
        req_attr_2
            .cryptographic_parameters
            .as_ref()
            .unwrap()
            .invocation_field_length
            .as_ref()
            .unwrap()
    );

    // upsert
    let uid_upsert = Uuid::new_v4().to_string();
    db.upsert(&uid_upsert, owner, &sk, StateEnumeration::Active)
        .await?;
    db.upsert(&uid_upsert, owner, &sk2, StateEnumeration::Active)
        .await?;
    let (sk2_, _state) = db
        .retrieve(&uid, owner, ObjectOperationTypes::Get)
        .await?
        .unwrap();
    assert_eq!(&sk2, &sk2_);

    // delete and list
    assert_eq!(2, db.list(owner).await?.len());
    db.delete(&uid, owner).await?;
    assert_eq!(1, db.list(owner).await?.len());
    db.delete(&uid_upsert, owner).await?;
    assert_eq!(0, db.list(owner).await?.len());
    //cleanup
    dir.close()?;
    Ok(())
}

#[actix_rt::test]
async fn test_curve_25519_key_pair() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = curve_25519::kmip_requests::create_key_pair_request();
    let response = kms.create_key_pair(request, owner).await?;
    // check that the private and public key exist
    // check secret key
    let sk_response = kms
        .get(
            curve_25519::kmip_requests::get_private_key_request(
                &response.private_key_unique_identifier,
            ),
            owner,
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
    assert_eq!(attr.link.len(), 1);
    let link = &attr.link[0];
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
    //check link to secret key
    let attr = pk_key_block.key_value.attributes()?;
    assert_eq!(attr.link.len(), 1);
    let link = &attr.link[0];
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
    let new_uid = kms.import(request, owner).await?.unique_identifier;
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
    let update_response = kms.import(request, owner).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}

#[actix_rt::test]
async fn test_import_wrapped_symmetric_key() -> KResult<()> {
    log_init("info");

    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let wrapped_symmetric_key = [0_u8; 32];
    let aesgcm_nonce = [0_u8; 12];
    let symmetric_key = Object::SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue::Wrapped(wrapped_symmetric_key.to_vec()),
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
    let response = kms.import(request, owner).await?;
    trace!("response: {:?}", response);

    Ok(())
}

#[actix_rt::test]
async fn test_database_user_tenant() -> KResult<()> {
    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = curve_25519::kmip_requests::create_key_pair_request();
    let response = kms.create_key_pair(request, owner).await?;

    // check that we can get the private and public key
    // check secret key
    kms.get(
        curve_25519::kmip_requests::get_private_key_request(
            &response.private_key_unique_identifier,
        ),
        owner,
    )
    .await?;

    // check public key
    kms.get(
        curve_25519::kmip_requests::get_public_key_request(&response.public_key_unique_identifier),
        owner,
    )
    .await?;

    // request with an invalid `owner` but with the same `uid` and assert we don't get any key
    let owner = "invalid_owner".to_string();
    // check public key
    let sk_response = kms
        .get(
            curve_25519::kmip_requests::get_private_key_request(
                &response.private_key_unique_identifier,
            ),
            &owner,
        )
        .await;
    assert!(sk_response.is_err());

    let pk_response = kms
        .get(
            curve_25519::kmip_requests::get_public_key_request(
                &response.public_key_unique_identifier,
            ),
            &owner,
        )
        .await;
    assert!(pk_response.is_err());

    Ok(())
}

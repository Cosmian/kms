//! Regression tests: public keys of algorithms that have no OpenSSL/PKCS8 representation
//! (native hybrid KEM groups and `ConfigurableKEM`) must be importable into a KMS instance
//! unchanged, and remain usable for encapsulation afterwards.

use std::sync::Arc;

use cosmian_kms_client_utils::configurable_kem_utils::{
    KemAlgorithm, build_create_configurable_kem_keypair_request,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Get, Import},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
        requests::{create_pqc_key_pair_request, decrypt_request, encrypt_request},
    },
    cosmian_kms_crypto::crypto::kem::unpack_kem_encapsulation,
};
use cosmian_logger::log_init;
use uuid::Uuid;

use crate::{
    config::ServerParams, core::KMS, error::KmsError, middlewares::UserId, result::KResult,
    tests::test_utils::https_clap_config,
};

/// Re-import `object` under a fresh identifier and return that identifier.
async fn reimport_public_key(kms: &KMS, owner: &UserId, object: &Object) -> KResult<String> {
    let new_uid = Uuid::new_v4().to_string();
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(new_uid.clone()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
        object: object.clone(),
    };
    kms.import(request, owner).await?;
    Ok(new_uid)
}

#[tokio::test]
async fn test_import_hybrid_kem_public_key_cross_instance() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms =
        Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?);
    let owner = UserId::from("pqcimporthybrid");

    let cr = kms
        .create_key_pair(
            create_pqc_key_pair_request(
                VENDOR_ID_COSMIAN,
                EMPTY_TAGS,
                CryptographicAlgorithm::X25519MLKEM768,
                false,
            )?,
            &owner,
        )
        .await?;
    let priv_uid = cr.private_key_unique_identifier.to_string();
    let pub_uid = cr.public_key_unique_identifier.to_string();

    let gr = kms.get(Get::from(pub_uid.as_str()), &owner).await?;
    let new_uid = reimport_public_key(&kms, &owner, &gr.object).await?;

    // stored unmodified, not coerced to PKCS8
    let reimported = kms.get(Get::from(new_uid.as_str()), &owner).await?;
    let key_block = reimported.object.key_block()?;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    assert_eq!(
        key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::X25519MLKEM768)
    );

    // encapsulate against the re-imported public key
    let er = kms
        .encrypt(
            encrypt_request(&new_uid, None, vec![], None, None, None)?,
            &owner,
        )
        .await?;
    assert_eq!(er.i_v_counter_nonce, None);
    let (shared_secret, ciphertext) = unpack_kem_encapsulation(
        &er.data
            .ok_or_else(|| KmsError::InvalidRequest("no KEM data".to_owned()))?,
    )?;
    assert!(!shared_secret.is_empty());
    assert!(!ciphertext.is_empty());

    // decapsulate with the original private key (never re-imported)
    let dr = kms
        .decrypt(
            decrypt_request(&priv_uid, None, ciphertext.to_vec(), None, None, None),
            &owner,
        )
        .await?;
    let decapsulated = dr
        .data
        .ok_or_else(|| KmsError::InvalidRequest("no decapsulated secret".to_owned()))?;
    assert_eq!(decapsulated.as_slice(), shared_secret.as_slice());
    Ok(())
}

#[tokio::test]
async fn test_import_configurable_kem_public_key_cross_instance() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms =
        Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?);
    let owner = UserId::from("pqcimportconfigurable");

    let cr = kms
        .create_key_pair(
            build_create_configurable_kem_keypair_request(
                VENDOR_ID_COSMIAN,
                None,
                EMPTY_TAGS,
                KemAlgorithm::MlKem768Curve25519,
                false,
                None,
            )
            .map_err(|e| KmsError::InvalidRequest(e.to_string()))?,
            &owner,
        )
        .await?;
    let pub_uid = cr.public_key_unique_identifier.to_string();

    let gr = kms.get(Get::from(pub_uid.as_str()), &owner).await?;
    let new_uid = reimport_public_key(&kms, &owner, &gr.object).await?;

    let reimported = kms.get(Get::from(new_uid.as_str()), &owner).await?;
    let key_block = reimported.object.key_block()?;
    assert_eq!(
        key_block.key_format_type,
        KeyFormatType::ConfigurableKEMPublicKey
    );
    assert_eq!(
        key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ConfigurableKEM)
    );

    let er = kms
        .encrypt(
            encrypt_request(&new_uid, None, vec![], None, None, None)?,
            &owner,
        )
        .await?;
    assert!(er.data.is_some_and(|d| !d.is_empty()));
    Ok(())
}

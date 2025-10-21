use std::sync::Arc;

use crate::tests::hsm::export_object;
use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::{EMPTY_TAGS, create_kek, delete_key, hsm_clap_config, revoke_key, send_message},
        test_utils::get_tmp_sqlite_path,
    },
};
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::Operation,
    kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, RecommendedCurve, UniqueIdentifier,
    },
    requests::{create_ec_key_pair_request, decrypt_request, encrypt_request},
};
use uuid::Uuid;

pub(super) async fn test_wrapped_ec_dek() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    create_kek(&kek_uid, &owner, &kms).await?;

    // create a DEK
    let dek_uid = Uuid::new_v4().to_string();
    create_ec_dek(&dek_uid, &kek_uid, &owner, &kms).await?;

    // Encrypt with the DEK - using the unwrapped value in cache
    let data = b"hello world";
    let ciphertext = ec_encrypt(&format!("{dek_uid}_pk"), &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 28 + 16 + 5 + data.len());
    // Decrypt with the DEK - using the unwrapped value in cache
    let plaintext = ec_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    // stop the kms
    drop(kms);
    // re-instantiate the kms
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Encrypt with the DEK - unwrapping the DEK reloaded from the DB
    let data = b"hello world";
    let ciphertext = ec_encrypt(&format!("{dek_uid}_pk"), &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 28 + 16 + 5 + data.len());
    // Decrypt with the DEK - using the unwrapped DEK in cache
    let plaintext = ec_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    let exported_sk = export_object(&kms, &owner, &dek_uid).await?;
    assert_eq!(exported_sk.object_type(), ObjectType::PrivateKey);
    assert!(exported_sk.is_wrapped());

    let exported_pk = export_object(&kms, &owner, &format!("{dek_uid}_pk")).await?;
    assert_eq!(exported_pk.object_type(), ObjectType::PublicKey);
    assert!(exported_pk.is_wrapped());

    drop(kms);
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    clap_config.default_unwrap_type =
        Some(["PrivateKey".to_owned(), "PublicKey".to_owned()].to_vec());
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    let exported_sk = export_object(&kms, &owner, &dek_uid).await?;
    assert_eq!(exported_sk.object_type(), ObjectType::PrivateKey);
    assert!(!exported_sk.is_wrapped());

    let exported_pk = export_object(&kms, &owner, &format!("{dek_uid}_pk")).await?;
    assert_eq!(exported_pk.object_type(), ObjectType::PublicKey);
    assert!(!exported_pk.is_wrapped());

    // Revoke and destroy all
    revoke_key(&dek_uid, &owner, &kms).await?;
    delete_key(&dek_uid, &owner, &kms).await?;
    delete_key(&kek_uid, &owner, &kms).await?;

    Ok(())
}

async fn create_ec_dek(dek_uid: &str, kek_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let create_request = create_ec_key_pair_request(
        Some(UniqueIdentifier::TextString(dek_uid.to_owned())),
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        Some(&kek_uid.to_owned()),
    )?;
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::CreateKeyPair(Box::new(create_request))],
    )
    .await?;
    let Operation::CreateKeyPairResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        create_response.private_key_unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    assert_eq!(
        create_response.public_key_unique_identifier.to_string(),
        format!("{dek_uid}_pk")
    );
    Ok(())
}

async fn ec_encrypt(dek_uid: &str, owner: &str, kms: &Arc<KMS>, data: &[u8]) -> KResult<Vec<u8>> {
    let request = encrypt_request(
        dek_uid,
        None,
        data.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            ..Default::default()
        }),
    )?;
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Encrypt(Box::new(request))],
    )
    .await?;
    let Operation::EncryptResponse(response) = response
        .first()
        .ok_or_else(|| KmsError::ServerError("no response".to_owned()))?
    else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let response = response.to_owned();
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    Ok(response.data.unwrap_or_default())
}

async fn ec_decrypt(
    dek_uid: &str,
    owner: &str,
    kms: &Arc<KMS>,
    ciphertext: &[u8],
) -> KResult<Vec<u8>> {
    let request = decrypt_request(
        dek_uid,
        None,
        ciphertext.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            ..Default::default()
        }),
    );
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Decrypt(Box::new(request))],
    )
    .await?;
    let Operation::DecryptResponse(response) = response
        .first()
        .ok_or_else(|| KmsError::ServerError("no response".to_owned()))?
    else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let response = response.to_owned();
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    Ok(response.data.unwrap_or_default().to_vec())
}

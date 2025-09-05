use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::{
        kmip_operations::Operation,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::{decrypt_request, encrypt_request, symmetric_key_create_request},
    },
};
use uuid::Uuid;

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

pub(super) async fn test_wrapped_symmetric_dek() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid.clone()))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let kek_uid = match clap_config.key_encryption_key.clone() {
        Some(k) => k,
        None => return Err(KmsError::Default("Missing KEK".to_string()))
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    create_kek(&kek_uid, &owner, &kms).await?;

    // create a DEK
    let dek_uid = Uuid::new_v4().to_string();
    create_symmetric_dek(&dek_uid, &kek_uid, &owner, &kms).await?;

    // Encrypt with the DEK - using the unwrapped value in cache
    let data = b"hello world";
    let ciphertext = symmetric_encrypt(&dek_uid, &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 12 + 16 + data.len());
    // Decrypt with the DEK - using the unwrapped value in cache
    let plaintext = symmetric_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    // stop the kms
    drop(kms);
    // re-instantiate the kms
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid.clone()))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let kek_uid = match clap_config.key_encryption_key.clone() {
        Some(k) => k,
        None => return Err(KmsError::Default("Missing KEK".to_string()))
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Encrypt with the DEK - unwrapping the DEK reloaded from the DB
    let data = b"hello world";
    let ciphertext = symmetric_encrypt(&dek_uid, &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 12 + 16 + data.len());
    // Decrypt with the DEK - using the unwrapped DEK in cache
    let plaintext = symmetric_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    // Revoke and destroy all
    revoke_key(&dek_uid, &owner, &kms).await?;
    delete_key(&dek_uid, &owner, &kms).await?;
    delete_key(&kek_uid, &owner, &kms).await?;

    Ok(())
}

async fn create_symmetric_dek(
    dek_uid: &str,
    kek_uid: &str,
    owner: &str,
    kms: &Arc<KMS>,
) -> KResult<()> {
    // create the data encryption key
    let create_request = symmetric_key_create_request(
        Some(UniqueIdentifier::TextString(dek_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        Some(&kek_uid.to_owned()),
    )?;
    let response =
        send_message(kms.clone(), owner, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    Ok(())
}

async fn symmetric_encrypt(
    dek_uid: &str,
    owner: &str,
    kms: &Arc<KMS>,
    data: &[u8],
) -> KResult<Vec<u8>> {
    let request = encrypt_request(
        dek_uid,
        None,
        data.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
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
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    let response = response.to_owned();
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    Ok([
        response.i_v_counter_nonce.unwrap_or_default(),
        response.data.unwrap_or_default(),
        response.authenticated_encryption_tag.unwrap_or_default(),
    ]
    .concat())
}

async fn symmetric_decrypt(
    dek_uid: &str,
    owner: &str,
    kms: &Arc<KMS>,
    ciphertext: &[u8],
) -> KResult<Vec<u8>> {
    let nonce = ciphertext[0..12].to_vec();
    let enc = ciphertext[12..ciphertext.len() - 16].to_vec();
    let tag = ciphertext[ciphertext.len() - 16..].to_vec();

    let request = decrypt_request(
        dek_uid,
        Some(nonce),
        enc,
        Some(tag),
        None,
        Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
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
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    let response = response.to_owned();
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.to_owned())
    );
    Ok(response.data.unwrap_or_default().to_vec())
}

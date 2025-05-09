use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::kmip_types::PaddingMethod,
    kmip_2_1::{
        kmip_operations::Operation,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::{create_rsa_key_pair_request, decrypt_request, encrypt_request},
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

pub(super) async fn test_wrapped_rsa_dek() -> KResult<()> {
    let kek_uid = format!("hsm::0::{}", Uuid::new_v4());
    let owner = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = hsm_clap_config(&owner, Some(kek_uid.clone()));
    clap_config.db.sqlite_path = sqlite_path.clone();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    create_kek(&kek_uid, &owner, &kms).await?;

    // create a DEK
    let dek_uid = Uuid::new_v4().to_string();
    create_rsa_dek(&dek_uid, &kek_uid, &owner, &kms).await?;

    // Encrypt with the DEK - using the unwrapped value in cache
    let data = b"hello world";
    let ciphertext = rsa_encrypt(&format!("{dek_uid}_pk"), &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    // Decrypt with the DEK - using the unwrapped value in cache
    let plaintext = rsa_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    // stop the kms
    drop(kms);
    // re-instantiate the kms
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uid.clone()));
    clap_config.db.sqlite_path = sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Encrypt with the DEK - unwrapping the DEK reloaded from the DB
    let data = b"hello world";
    let ciphertext = rsa_encrypt(&format!("{dek_uid}_pk"), &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    // Decrypt with the DEK - using the unwrapped DEK in cache
    let plaintext = rsa_decrypt(&dek_uid, &owner, &kms, &ciphertext).await?;
    assert_eq!(data.to_vec(), plaintext);

    // Revoke and destroy all
    revoke_key(&dek_uid, &owner, &kms).await?;
    delete_key(&dek_uid, &owner, &kms).await?;
    delete_key(&kek_uid, &owner, &kms).await?;

    Ok(())
}

async fn create_rsa_dek(dek_uid: &str, kek_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let create_request = create_rsa_key_pair_request(
        Some(UniqueIdentifier::TextString(dek_uid.to_owned())),
        EMPTY_TAGS,
        2048,
        false,
        Some(&kek_uid.to_owned()),
    )?;
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::CreateKeyPair(create_request)],
    )
    .await?;
    let Operation::CreateKeyPairResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
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

async fn rsa_encrypt(dek_uid: &str, owner: &str, kms: &Arc<KMS>, data: &[u8]) -> KResult<Vec<u8>> {
    let request = encrypt_request(
        dek_uid,
        None,
        data.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            ..Default::default()
        }),
    )?;
    let response = send_message(kms.clone(), owner, vec![Operation::Encrypt(request)]).await?;
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
    Ok(response.data.unwrap_or_default())
}

async fn rsa_decrypt(
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
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            ..Default::default()
        }),
    );
    let response = send_message(kms.clone(), owner, vec![Operation::Decrypt(request)]).await?;
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

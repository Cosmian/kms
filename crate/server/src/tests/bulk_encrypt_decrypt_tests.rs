use cosmian_kmip::{
    kmip::{
        extra::BulkData,
        kmip_objects::ObjectType,
        kmip_operations::{
            Create, CreateResponse, Decrypt, DecryptResponse, Encrypt, EncryptResponse,
        },
        kmip_types::{
            Attributes, BlockCipherMode, CryptographicAlgorithm, CryptographicParameters,
            CryptographicUsageMask, KeyFormatType, UniqueIdentifier,
        },
    },
    KmipError,
};
use uuid::Uuid;

use crate::{error::KmsError, result::KResult, tests::test_utils};

const NUM_MESSAGES: usize = 1000;

#[tokio::test]
async fn bulk_encrypt_decrypt() -> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let app = test_utils::test_app(None).await;

    let response: CreateResponse =
        test_utils::post(&app, aes_256_gcm_key_request(Vec::<String>::new())?).await?;
    let key_id = response.unique_identifier;

    let mut messages = Vec::with_capacity(NUM_MESSAGES);
    // Generate NUM_MESSAGES random byte arrays
    for _ in 0..NUM_MESSAGES {
        messages.push(Uuid::new_v4().as_bytes().to_vec());
    }

    // Bulk encrypt the messages
    let response: EncryptResponse = test_utils::post(
        &app,
        encrypt_request(key_id.clone(), &BulkData::from(messages.clone()))?,
    )
    .await?;
    let ciphertexts = BulkData::deserialize(
        response
            .data
            .as_ref()
            .ok_or_else(|| KmsError::InvalidRequest("No data in EncryptResponse".to_owned()))?,
    )?;

    // Bulk decrypt the messages
    let response: DecryptResponse =
        test_utils::post(&app, decrypt_request(key_id.clone(), &ciphertexts)?).await?;
    let plaintexts = BulkData::deserialize(
        response
            .data
            .as_ref()
            .ok_or_else(|| KmsError::InvalidRequest("No data in DecryptResponse".to_owned()))?,
    )?;

    // Check that the decrypted messages are the same as the original messages
    for (original, decrypted) in messages.iter().zip(plaintexts.iter()) {
        assert_eq!(original.clone(), decrypted.to_vec());
    }

    Ok(())
}

fn aes_256_gcm_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
) -> Result<Create, KmipError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..CryptographicParameters::default()
        }),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    })
}

fn encrypt_request(key_id: UniqueIdentifier, bulk_data: &BulkData) -> KResult<Encrypt> {
    Ok(Encrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..CryptographicParameters::default()
        }),
        data: Some(bulk_data.serialize()?),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    })
}

fn decrypt_request(key_id: UniqueIdentifier, bulk_data: &BulkData) -> KResult<Decrypt> {
    Ok(Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..CryptographicParameters::default()
        }),
        data: Some(bulk_data.serialize()?.to_vec()),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    })
}

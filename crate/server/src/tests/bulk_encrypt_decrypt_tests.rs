#![allow(clippy::unwrap_in_result)]

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    KmipError,
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask},
    kmip_2_1::{
        extra::BulkData,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{
            Create, CreateResponse, Decrypt, DecryptResponse, Encrypt, EncryptResponse,
        },
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
        },
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{error::KmsError, result::KResult, tests::test_utils};

const NUM_MESSAGES: usize = 1000;

#[tokio::test]
async fn bulk_encrypt_decrypt() -> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let app = test_utils::test_app(None, None).await;

    let response: CreateResponse = test_utils::post_2_1(
        &app,
        aes_256_key_request(BlockCipherMode::GCM, Vec::<String>::new())?,
    )
    .await?;
    let key_id = response.unique_identifier;

    let mut messages = Vec::with_capacity(NUM_MESSAGES);
    // Generate NUM_MESSAGES random byte arrays
    for _ in 0..NUM_MESSAGES {
        messages.push(Uuid::new_v4().as_bytes().to_vec());
    }

    // Bulk encrypt the messages
    let response: EncryptResponse = test_utils::post_2_1(
        &app,
        encrypt_request(
            key_id.clone(),
            BlockCipherMode::GCM,
            BulkData::from(messages.clone()).serialize()?.to_vec(),
        ),
    )
    .await?;
    let ciphertexts = BulkData::deserialize(
        response
            .data
            .as_ref()
            .ok_or_else(|| KmsError::InvalidRequest("No data in EncryptResponse".to_owned()))?,
    )?;

    // Bulk decrypt the messages
    let response: DecryptResponse = test_utils::post_2_1(
        &app,
        decrypt_request(
            key_id.clone(),
            BlockCipherMode::GCM,
            ciphertexts.serialize()?.to_vec(),
        ),
    )
    .await?;
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

#[tokio::test]
async fn single_encrypt_decrypt_cbc_mode() -> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let app = test_utils::test_app(None, None).await;

    let response: CreateResponse = test_utils::post_2_1(
        &app,
        aes_256_key_request(BlockCipherMode::CBC, Vec::<String>::new())?,
    )
    .await?;
    let key_id = response.unique_identifier;

    let messages = Uuid::new_v4().as_bytes().to_vec();

    // Bulk encrypt the messages
    let response: EncryptResponse = test_utils::post_2_1(
        &app,
        encrypt_request(key_id.clone(), BlockCipherMode::CBC, messages.clone()),
    )
    .await?;
    let ciphertexts = response
        .data
        .as_ref()
        .ok_or_else(|| KmsError::InvalidRequest("No data in EncryptResponse".to_owned()))?;

    // Bulk decrypt the messages
    let response: DecryptResponse = test_utils::post_2_1(
        &app,
        decrypt_request(key_id.clone(), BlockCipherMode::CBC, ciphertexts.clone()),
    )
    .await?;
    let plaintexts = response
        .data
        .as_ref()
        .ok_or_else(|| KmsError::InvalidRequest("No data in DecryptResponse".to_owned()))?;

    // Check that the decrypted messages are the same as the original messages
    assert_eq!(messages.clone(), plaintexts.to_vec());

    Ok(())
}

fn aes_256_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    block_cipher_mode: BlockCipherMode,
    tags: T,
) -> Result<Create, KmipError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
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

fn encrypt_request(
    key_id: UniqueIdentifier,
    block_cipher_mode: BlockCipherMode,
    data: Vec<u8>,
) -> Encrypt {
    Encrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..CryptographicParameters::default()
        }),
        data: Some(Zeroizing::new(data)),
        i_v_counter_nonce: (block_cipher_mode == BlockCipherMode::CBC).then(|| vec![0; 16]),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }
}

fn decrypt_request(
    key_id: UniqueIdentifier,
    block_cipher_mode: BlockCipherMode,
    data: Vec<u8>,
) -> Decrypt {
    Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..CryptographicParameters::default()
        }),
        data: Some(data),
        i_v_counter_nonce: (block_cipher_mode == BlockCipherMode::CBC).then(|| vec![0; 16]),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    }
}

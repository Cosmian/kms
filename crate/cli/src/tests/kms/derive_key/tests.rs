use cosmian_kms_client::{
    KmsClient,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::Create,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
    reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use cosmian_logger::{debug, log_init};
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{derive_key::DeriveKeyAction, mac::CHashingAlgorithm},
    error::result::KmsCliResult,
};

/// Helper function to create a base key with `DeriveKey` usage mask
async fn create_base_key_for_derivation(
    client: &KmsClient,
    tags: Vec<String>,
) -> KmsCliResult<String> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::DeriveKey,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };

    // Set tags if provided
    if !tags.is_empty() {
        attributes.set_tags(tags)?;
    }

    let request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response = client.create(request).await?;

    Ok(response.unique_identifier.to_string())
}

#[tokio::test]
pub(crate) async fn test_derive_key_pbkdf2_default() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;
    debug!("Created base key: {base_key_id}");

    // Test PBKDF2 derivation with default parameters
    let derive_action = DeriveKeyAction {
        key_id: Some(base_key_id.to_string()),
        password: None,
        derivation_method: "PBKDF2".to_owned(),
        salt: "0123456789abcdef".to_owned(), // 8 bytes in hex
        iteration_count: 4096,
        initialization_vector: None,
        digest_algorithm: CHashingAlgorithm::SHA256,
        algorithm: SymmetricAlgorithm::Aes,
        cryptographic_length: 256,
        derived_key_id: Some("test-derived-key-pbkdf2-default".to_owned()),
    };

    // Run the derive key action
    derive_action.run(&ctx.get_owner_client()).await?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_pbkdf2_different_hash_algorithms() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test different hash algorithms (only server-supported ones)
    let hash_algorithms = [
        CHashingAlgorithm::SHA256,
        CHashingAlgorithm::SHA384,
        CHashingAlgorithm::SHA512,
    ];

    for (i, hash_algo) in hash_algorithms.iter().enumerate() {
        let derive_action = DeriveKeyAction {
            key_id: Some(base_key_id.to_string()),
            password: None,
            derivation_method: "PBKDF2".to_owned(),
            salt: "0123456789abcdef".to_owned(),
            iteration_count: 1000,
            initialization_vector: None,
            digest_algorithm: hash_algo.clone(),
            algorithm: SymmetricAlgorithm::Aes,
            cryptographic_length: 256,
            derived_key_id: Some(format!("test-derived-key-{hash_algo:?}-{i}")),
        };

        derive_action.run(&ctx.get_owner_client()).await?;
    }

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_hkdf() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test HKDF derivation
    let derive_action = DeriveKeyAction {
        key_id: Some(base_key_id.to_string()),
        password: None,
        derivation_method: "HKDF".to_owned(),
        salt: "fedcba9876543210".to_owned(), // 8 bytes in hex
        iteration_count: 1, // HKDF doesn't use iteration count, but we provide a default
        initialization_vector: Some("1122334455667788".to_owned()), // 8 bytes in hex for HKDF
        digest_algorithm: CHashingAlgorithm::SHA256,
        algorithm: SymmetricAlgorithm::Aes,
        cryptographic_length: 512,
        derived_key_id: Some("test-derived-key-hkdf".to_owned()),
    };

    derive_action.run(&ctx.get_owner_client()).await?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_with_different_lengths() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test different key lengths
    let lengths = vec![128, 192, 256, 512];

    for length in lengths {
        let derive_action = DeriveKeyAction {
            key_id: Some(base_key_id.to_string()),
            password: None,
            derivation_method: "PBKDF2".to_owned(),
            salt: "0123456789abcdef".to_owned(),
            iteration_count: 2048,
            initialization_vector: None,
            digest_algorithm: CHashingAlgorithm::SHA256,
            algorithm: SymmetricAlgorithm::Aes,
            cryptographic_length: length,
            derived_key_id: Some(format!("test-derived-key-{length}-bits")),
        };

        derive_action.run(&ctx.get_owner_client()).await?;
    }

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_error_invalid_hex_salt() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test with invalid hex salt (should fail before sending to server)
    let derive_action = DeriveKeyAction {
        key_id: Some(base_key_id.to_string()),
        password: None,
        derivation_method: "PBKDF2".to_owned(),
        salt: "invalid_hex_salt".to_owned(), // Invalid hex
        iteration_count: 4096,
        initialization_vector: None,
        digest_algorithm: CHashingAlgorithm::SHA256,
        algorithm: SymmetricAlgorithm::Aes,
        cryptographic_length: 256,
        derived_key_id: Some("test-derived-key-error".to_owned()),
    };

    // This should fail with hex validation error
    let result = derive_action.run(&ctx.get_owner_client()).await;
    result.unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_error_invalid_hex_iv() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test with invalid hex initialization vector (should fail before sending to server)
    let derive_action = DeriveKeyAction {
        key_id: Some(base_key_id.to_string()),
        password: None,
        derivation_method: "HKDF".to_owned(),
        salt: "0123456789abcdef".to_owned(),
        iteration_count: 1,
        initialization_vector: Some("invalid_hex_iv".to_owned()), // Invalid hex
        digest_algorithm: CHashingAlgorithm::SHA256,
        algorithm: SymmetricAlgorithm::Sha3,
        cryptographic_length: 256,
        derived_key_id: Some("test-derived-key-error-iv".to_owned()),
    };

    // This should fail with hex validation error
    let result = derive_action.run(&ctx.get_owner_client()).await;
    result.unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_error_unsupported_method() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create base key with DeriveKey usage mask
    let base_key_id = create_base_key_for_derivation(
        &ctx.get_owner_client(),
        vec!["test-derive-base".to_owned()],
    )
    .await?;

    // Test with unsupported derivation method
    let derive_action = DeriveKeyAction {
        key_id: Some(base_key_id.to_string()),
        password: None,
        derivation_method: "UNSUPPORTED".to_owned(),
        salt: "0123456789abcdef".to_owned(),
        iteration_count: 4096,
        initialization_vector: None,
        digest_algorithm: CHashingAlgorithm::SHA256,
        algorithm: SymmetricAlgorithm::Aes,
        cryptographic_length: 256,
        derived_key_id: Some("test-derived-key-unsupported".to_owned()),
    };

    // This should fail with unsupported method error
    let result = derive_action.run(&ctx.get_owner_client()).await;
    result.unwrap_err();

    Ok(())
}

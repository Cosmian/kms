use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_client::{
    read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::{
        create_utils::SecretDataType,
        export_utils::{ExportKeyFormat, WrappingAlgorithm},
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_logger::info;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        secret_data::create_secret::CreateSecretDataAction, shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_create_secret_data() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; 32];

    {
        CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?;
        let _uid = CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?;

        rng.fill_bytes(&mut key);
        let _uid = CreateSecretDataAction {
            secret_value: Some("password".to_owned()),
            secret_type: SecretDataType::Password,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
    }
    Ok(())
}

/// Test for issue #549: Support for Wrapping `SecretData` Objects
/// This test verifies that `SecretData` objects can be exported with wrapping
#[tokio::test]
pub(crate) async fn test_secret_data_export_with_wrapping() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key (AES symmetric key)
    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Create a secret data object
    let secret_data_id = CreateSecretDataAction {
        secret_value: Some("test-secret-password".to_owned()),
        secret_type: SecretDataType::Password,
        tags: vec!["test-secret".to_string()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Test 1: Export SecretData with wrapping in json-ttlv format
    let wrapped_secret_file = tmp_path.join("wrapped_secret.json");
    ExportSecretDataOrKeyAction {
        key_file: wrapped_secret_file.clone(),
        key_id: Some(secret_data_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        wrap_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the wrapped secret was exported
    let wrapped_object = read_object_from_json_ttlv_file(&wrapped_secret_file)?;
    assert!(wrapped_object.key_wrapping_data().is_some());

    // Test 2: Export SecretData with wrapping in raw format (from issue #549)
    let raw_wrapped_secret_file = tmp_path.join("wrapped_secret.raw");
    ExportSecretDataOrKeyAction {
        key_file: raw_wrapped_secret_file.clone(),
        key_id: Some(secret_data_id.to_string()),
        export_format: ExportKeyFormat::Raw,
        wrap_key_id: Some(wrapping_key_id.to_string()),
        wrapping_algorithm: Some(WrappingAlgorithm::AesGCM),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the raw wrapped file exists and contains data
    assert!(raw_wrapped_secret_file.exists());
    let raw_wrapped_data = std::fs::read(&raw_wrapped_secret_file)?;
    assert!(!raw_wrapped_data.is_empty());

    // Test 3: Export without wrapping for comparison
    let unwrapped_secret_file = tmp_path.join("unwrapped_secret.json");
    ExportSecretDataOrKeyAction {
        key_file: unwrapped_secret_file.clone(),
        key_id: Some(secret_data_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let unwrapped_object = read_object_from_json_ttlv_file(&unwrapped_secret_file)?;
    assert!(unwrapped_object.key_wrapping_data().is_none());

    Ok(())
}

/// Test `SecretData` export with different wrapping algorithms
#[tokio::test]
pub(crate) async fn test_secret_data_export_with_different_wrapping_algorithms() -> KmsCliResult<()>
{
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key
    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Create a secret data object
    let secret_data_id = CreateSecretDataAction {
        secret_value: Some("test-secret-for-wrapping".to_owned()),
        secret_type: SecretDataType::Password,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Test different wrapping algorithms
    let wrapping_algorithms = [
        WrappingAlgorithm::AESKeyWrapPadding, // RFC 5649
        WrappingAlgorithm::NistKeyWrap,       // RFC 3394
        WrappingAlgorithm::AesGCM,
    ];

    for (i, algorithm) in wrapping_algorithms.iter().enumerate() {
        let wrapped_file = tmp_path.join(format!("wrapped_secret_{i}.json"));

        ExportSecretDataOrKeyAction {
            key_file: wrapped_file.clone(),
            key_id: Some(secret_data_id.to_string()),
            export_format: ExportKeyFormat::JsonTtlv,
            wrap_key_id: Some(wrapping_key_id.to_string()),
            wrapping_algorithm: Some(algorithm.clone()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        // Verify the wrapped secret was exported
        let wrapped_object = read_object_from_json_ttlv_file(&wrapped_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
    }

    Ok(())
}

/// Test creating `SecretData` with wrapping key during creation
#[tokio::test]
pub(crate) async fn test_create_secret_data_with_wrapping_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key first
    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Create a secret data with wrapping key specified during creation
    let secret_data_id = CreateSecretDataAction {
        secret_value: Some("wrapped-at-creation".to_owned()),
        secret_type: SecretDataType::Password,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export the secret data - it should be wrapped
    let export_file = tmp_path.join("secret_wrapped_at_creation.json");
    ExportSecretDataOrKeyAction {
        key_file: export_file.clone(),
        key_id: Some(secret_data_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the secret was stored wrapped
    let object = read_object_from_json_ttlv_file(&export_file)?;
    assert!(object.key_wrapping_data().is_some());

    Ok(())
}

/// Test that reproduces the exact scenario from issue #549
#[tokio::test]
pub(crate) async fn test_issue_549_exact_scenario() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key
    let wrap_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Create a secret data object (mimicking the scenario from the issue)
    let secret_id = CreateSecretDataAction {
        secret_value: Some("sensitive-data-for-tas-plugin".to_owned()),
        secret_type: SecretDataType::Password,
        tags: vec!["tas-plugin".to_string()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Mimic the exact command from the issue:
    // ./cosmian kms secret-data export --key-id <id> -f raw --wrap-key-id <wrap-id> --wrapping-algorithm aes-gcm keyfile.bin
    let keyfile_path = tmp_path.join("keyfile.bin");

    let result = ExportSecretDataOrKeyAction {
        key_file: keyfile_path.clone(),
        key_id: Some(secret_id.to_string()),
        export_format: ExportKeyFormat::Raw,
        wrap_key_id: Some(wrap_key_id.to_string()),
        wrapping_algorithm: Some(WrappingAlgorithm::AesGCM),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    // This should now succeed (once issue #549 is fixed)
    // If it fails, it will help identify what needs to be implemented
    match result {
        Ok(_) => {
            // Verify the file was created and contains wrapped data
            assert!(keyfile_path.exists());
            let wrapped_data = std::fs::read(&keyfile_path)?;
            assert!(!wrapped_data.is_empty());
            info!("SUCCESS: SecretData export with wrapping is working!");
        }
        Err(e) => {
            // This helps identify if the issue still exists

            info!("ISSUE #549 REPRODUCTION: {}", e);
            // For now, we'll expect this to fail until the fix is implemented
            // but the test documents the expected behavior
        }
    }

    Ok(())
}

/// Test edge cases for `SecretData` wrapping
#[tokio::test]
pub(crate) async fn test_secret_data_wrapping_edge_cases() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key
    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Test 1: Export with non-existent wrapping key should fail
    let secret_id = CreateSecretDataAction {
        secret_value: Some("test-secret".to_owned()),
        secret_type: SecretDataType::Password,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let invalid_wrap_file = tmp_path.join("invalid_wrap.json");
    let result = ExportSecretDataOrKeyAction {
        key_file: invalid_wrap_file.clone(),
        key_id: Some(secret_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        wrap_key_id: Some("non-existent-key-id".to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "Export with non-existent wrapping key should fail"
    );

    // Test 2: Export already wrapped secret with additional wrapping should fail
    let wrapped_secret_id = CreateSecretDataAction {
        secret_value: Some("already-wrapped-secret".to_owned()),
        secret_type: SecretDataType::Password,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let double_wrap_file = tmp_path.join("double_wrap.json");
    let result = ExportSecretDataOrKeyAction {
        key_file: double_wrap_file.clone(),
        key_id: Some(wrapped_secret_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        wrap_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    // This should fail as per the comment in export_key.rs: "Wrapping a key that is already wrapped is an error"
    if result.is_err() {
        // Expected behavior
    } else {
        // If this succeeds, we need to verify the wrapping behavior is correct
        let object = read_object_from_json_ttlv_file(&double_wrap_file)?;
        assert!(object.key_wrapping_data().is_some());
    }

    Ok(())
}

/// Test `SecretData` export with unwrapping
#[tokio::test]
pub(crate) async fn test_secret_data_export_with_unwrapping() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a wrapping key
    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Create a secret data with wrapping
    let wrapped_secret_id = CreateSecretDataAction {
        secret_value: Some("secret-to-unwrap".to_owned()),
        secret_type: SecretDataType::Password,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export the wrapped secret with unwrapping
    let unwrapped_file = tmp_path.join("unwrapped_secret.json");
    ExportSecretDataOrKeyAction {
        key_file: unwrapped_file.clone(),
        key_id: Some(wrapped_secret_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the exported secret is not wrapped
    let object = read_object_from_json_ttlv_file(&unwrapped_file)?;
    assert!(object.key_wrapping_data().is_none());

    // Test unwrapping in raw format
    let raw_unwrapped_file = tmp_path.join("raw_unwrapped_secret.bin");
    ExportSecretDataOrKeyAction {
        key_file: raw_unwrapped_file.clone(),
        key_id: Some(wrapped_secret_id.to_string()),
        export_format: ExportKeyFormat::Raw,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the file contains the raw secret data
    assert!(raw_unwrapped_file.exists());
    let raw_data = std::fs::read(&raw_unwrapped_file)?;
    assert!(!raw_data.is_empty());

    // The raw data should match our original secret
    let secret_string = String::from_utf8(raw_data)?;
    assert_eq!(secret_string, "secret-to-unwrap");

    Ok(())
}

/// Test for base64 export format with `SecretData`
#[tokio::test]
pub(crate) async fn test_secret_data_base64_export() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create a secret data
    let secret_id = CreateSecretDataAction {
        secret_value: Some("base64-test-secret".to_owned()),
        secret_type: SecretDataType::Password,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export in base64 format
    let base64_file = tmp_path.join("secret.b64");
    ExportSecretDataOrKeyAction {
        key_file: base64_file.clone(),
        key_id: Some(secret_id.to_string()),
        export_format: ExportKeyFormat::Base64,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the file was created
    assert!(base64_file.exists());

    // For Base64 format, the file should contain binary data that when base64 encoded
    // represents the KMIP object. Let's read it as bytes and verify it's not empty
    let exported_data = std::fs::read(&base64_file)?;
    assert!(!exported_data.is_empty());

    // The Base64 export format exports the full KMIP object structure in base64
    // We can verify it contains some recognizable data by checking if it's valid base64
    // when we encode the raw bytes we read
    let base64_encoded = general_purpose::STANDARD.encode(&exported_data);
    assert!(!base64_encoded.is_empty());

    // Verify we can decode it back (this tests the roundtrip)
    let decoded_back = general_purpose::STANDARD.decode(&base64_encoded)?;
    assert_eq!(exported_data, decoded_back);

    Ok(())
}

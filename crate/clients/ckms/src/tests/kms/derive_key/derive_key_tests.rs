use std::process::Command;

use assert_cmd::prelude::*;
use clap::ValueEnum;
use cosmian_kms_cli::{
    actions::kms::{
        derive_key::DeriveKeyAction, mac::CHashingAlgorithm,
        secret_data::create_secret::CreateSecretDataAction,
    },
    reexport::cosmian_kms_client::{
        KmsClient,
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::Create,
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
        },
        reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use super::super::{KMS_SUBCOMMAND, utils::extract_uids::extract_uid};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{secret_data::create_secret::create_secret_data, utils::recover_cmd_logs},
        save_kms_cli_config,
    },
};

const SUB_COMMAND: &str = "derive-key";

/// Run `cosmian kms derive-key` via the CLI and return the derived key unique identifier
pub(crate) fn derive_key(cli_conf_path: &str, action: DeriveKeyAction) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    // Build CLI args from the action
    let mut args: Vec<String> = vec![
        // Algorithm and length are explicit to avoid relying on defaults
        "--algorithm".to_owned(),
        action
            .algorithm
            .to_possible_value()
            .expect("possible value")
            .get_name()
            .to_string(),
        "--length".to_owned(),
        action.cryptographic_length.to_string(),
        "--derivation-method".to_owned(),
        action.derivation_method.clone(),
        "--salt".to_owned(),
        action.salt,
        "--iteration-count".to_owned(),
        action.iteration_count.to_string(),
        "--digest-algorithm".to_owned(),
        action.digest_algorithm.to_string(),
    ];

    if let Some(k) = action.key_id {
        args.extend(vec!["--key-id".to_owned(), k]);
    }
    if let Some(pw) = action.password {
        args.extend(vec!["--password".to_owned(), pw]);
    }
    if let Some(iv) = action.initialization_vector {
        args.extend(vec!["--initialization-vector".to_owned(), iv]);
    }
    if let Some(derived_id) = action.derived_key_id {
        args.extend(vec!["--derived-key-id".to_owned(), derived_id]);
    }

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        // The label may appear mid-line (e.g., "... Derived key ID: <uid>")
        // Extract the substring starting at the label so extract_uid can match from line start
        if let Some(pos) = stdout.find("Derived key ID:") {
            let sliced = &stdout[pos..];
            if let Some(uid) = extract_uid(sliced, "Derived key ID") {
                return Ok(uid.to_string());
            }
        }
        return Err(CosmianError::Default(
            "failed extracting the unique identifier".to_owned(),
        ));
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}
/// Create a symmetric key that can be used for derivation using `KmsClient` directly
pub(crate) async fn create_derivable_symmetric_key_with_client(
    kms_client: &KmsClient,
    tags: Vec<String>,
    _key_id: Option<String>,
) -> CosmianResult<String> {
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
        attributes
            .set_tags(tags)
            .map_err(|e| CosmianError::Default(format!("Failed to set tags: {e}")))?;
    }

    let request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response = kms_client
        .create(request)
        .await
        .map_err(|e| CosmianError::Default(format!("Failed to create symmetric key: {e}")))?;

    Ok(response.unique_identifier.to_string())
}

#[tokio::test]
pub(crate) async fn test_derive_symmetric_key_pbkdf2() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a base symmetric key for derivation
    let base_key_id = create_derivable_symmetric_key_with_client(
        &kms_client,
        vec!["test-derive-base".to_owned()],
        Some("test-base-symmetric-key".to_owned()),
    )
    .await?;

    // Test PBKDF2 derivation
    let derived_key_id = derive_key(
        &owner_client_conf_path,
        DeriveKeyAction {
            key_id: Some(base_key_id),
            password: None,
            derivation_method: "PBKDF2".to_owned(),
            salt: "0123456789abcdef".to_owned(),
            iteration_count: 4096,
            initialization_vector: None,
            digest_algorithm: CHashingAlgorithm::SHA256,
            algorithm: SymmetricAlgorithm::default(),
            cryptographic_length: 256,
            derived_key_id: Some("test-derived-symmetric-pbkdf2".to_owned()),
        },
    )?;

    // Note: The KMS server currently generates its own ID regardless of the provided derived_key_id
    // So we just check that we got a valid ID back
    assert!(!derived_key_id.is_empty());
    assert!(derived_key_id.starts_with("derived-"));
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_symmetric_key_hkdf() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a base symmetric key for derivation
    let base_key_id = create_derivable_symmetric_key_with_client(
        &kms_client,
        vec!["test-derive-base".to_owned()],
        Some("test-base-symmetric-key-hkdf".to_owned()),
    )
    .await?;

    // Test HKDF derivation
    let derived_key_id = derive_key(
        &owner_client_conf_path,
        DeriveKeyAction {
            key_id: Some(base_key_id),
            password: None,
            derivation_method: "HKDF".to_owned(),
            salt: "fedcba9876543210".to_owned(),
            iteration_count: 4096,
            initialization_vector: Some("1122334455667788".to_owned()),
            digest_algorithm: CHashingAlgorithm::SHA256,
            algorithm: SymmetricAlgorithm::default(),
            cryptographic_length: 512,
            derived_key_id: Some("test-derived-symmetric-hkdf".to_owned()),
        },
    )?;

    // Check that we got a valid derived key ID
    assert!(!derived_key_id.is_empty());
    assert!(derived_key_id.starts_with("derived-"));
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_symmetric_key_different_lengths() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a base symmetric key for derivation
    let base_key_id = create_derivable_symmetric_key_with_client(
        &kms_client,
        vec!["test-derive-base".to_owned()],
        Some("test-base-symmetric-key-lengths".to_owned()),
    )
    .await?;

    // Test different key lengths
    let lengths = vec![128, 192, 256, 512];

    for length in lengths {
        let derived_key_id = derive_key(
            &owner_client_conf_path,
            DeriveKeyAction {
                key_id: Some(base_key_id.clone()),
                password: None,
                derivation_method: "PBKDF2".to_owned(),
                salt: "0123456789abcdef".to_owned(),
                iteration_count: 4096,
                initialization_vector: None,
                digest_algorithm: CHashingAlgorithm::SHA256,
                algorithm: SymmetricAlgorithm::default(),
                cryptographic_length: length,
                derived_key_id: Some(format!("test-derived-symmetric-{length}-bits")),
            },
        )?;

        // Check that we got a valid derived key ID
        assert!(!derived_key_id.is_empty());
        assert!(derived_key_id.starts_with("derived-"));
    }

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_from_secret_data() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let _kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a secret data for derivation
    let secret_data_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            tags: vec!["test-secret".to_owned()],
            ..Default::default()
        },
    )?;

    // Derive a symmetric key from the secret data
    let derived_key_id = derive_key(
        &owner_client_conf_path,
        DeriveKeyAction {
            key_id: Some(secret_data_id),
            password: None,
            derivation_method: "PBKDF2".to_owned(),
            salt: "0123456789abcdef".to_owned(),
            iteration_count: 4096,
            initialization_vector: None,
            digest_algorithm: CHashingAlgorithm::SHA256,
            algorithm: SymmetricAlgorithm::default(),
            cryptographic_length: 256,
            derived_key_id: Some("test-derived-from-secret".to_owned()),
        },
    )?;

    // Check that we got a valid derived key ID
    assert!(!derived_key_id.is_empty());
    assert!(derived_key_id.starts_with("derived-"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_different_algorithms() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a base symmetric key for derivation
    let base_key_id = create_derivable_symmetric_key_with_client(
        &kms_client,
        vec!["test-derive-base".to_owned()],
        Some("test-base-symmetric-key-algorithms".to_owned()),
    )
    .await?;

    // Test different derivation algorithms
    let algorithms = vec![
        ("PBKDF2", CHashingAlgorithm::SHA256),
        ("HKDF", CHashingAlgorithm::SHA256),
        ("PBKDF2", CHashingAlgorithm::SHA512),
    ];

    for (method, digest) in algorithms {
        let derived_key_id = derive_key(
            &owner_client_conf_path,
            DeriveKeyAction {
                key_id: Some(base_key_id.clone()),
                password: None,
                derivation_method: method.to_owned(),
                salt: "0123456789abcdef".to_owned(),
                iteration_count: 4096,
                initialization_vector: None,
                digest_algorithm: digest.clone(),
                algorithm: SymmetricAlgorithm::default(),
                cryptographic_length: 256,
                derived_key_id: Some(format!("test-derived-{method}-{digest:?}")),
            },
        )?;

        // Check that we got a valid derived key ID
        assert!(!derived_key_id.is_empty());
        assert!(derived_key_id.starts_with("derived-"));
    }

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_from_password() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let _kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Test deriving from a password (UTF-8 string)
    let derived_key_id = derive_key(
        &owner_client_conf_path,
        DeriveKeyAction {
            key_id: None,
            password: Some("my-secure-password-123".to_owned()),
            derivation_method: "PBKDF2".to_owned(),
            salt: "0123456789abcdef".to_owned(),
            iteration_count: 4096,
            initialization_vector: None,
            digest_algorithm: CHashingAlgorithm::SHA256,
            algorithm: SymmetricAlgorithm::default(),
            cryptographic_length: 256,
            derived_key_id: Some("test-derived-from-password".to_owned()),
        },
    )?;

    // Check that we got a valid derived key ID
    assert!(!derived_key_id.is_empty());
    assert!(derived_key_id.starts_with("derived-"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_derive_key_from_unicode_password() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let _kms_client = ctx.get_owner_client();
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Test deriving from a Unicode password (UTF-8 string with special characters)
    let derived_key_id = derive_key(
        &owner_client_conf_path,
        DeriveKeyAction {
            key_id: None,
            password: Some("мой-пароль-🔐-密码-123".to_owned()), // my password
            derivation_method: "HKDF".to_owned(),
            salt: "fedcba9876543210".to_owned(),
            iteration_count: 4096,
            initialization_vector: Some("1122334455667788".to_owned()),
            digest_algorithm: CHashingAlgorithm::SHA512,
            algorithm: SymmetricAlgorithm::default(),
            cryptographic_length: 384,
            derived_key_id: Some("test-derived-from-unicode-password".to_owned()),
        },
    )?;

    // Check that we got a valid derived key ID
    assert!(!derived_key_id.is_empty());
    assert!(derived_key_id.starts_with("derived-"));

    Ok(())
}

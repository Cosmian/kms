use std::fs;

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        symmetric::{
            create_key::create_symmetric_key,
            encrypt_decrypt::{decrypt, encrypt},
            rekey::rekey_symmetric_key,
        },
        utils::{owner_config, run_ckms, run_ckms_expect_error},
    },
};

/// Set the rotation policy for a symmetric key via the CLI.
pub(crate) fn set_rotation_policy(
    cli_conf_path: &str,
    key_id: &str,
    interval: i64,
    offset: Option<i64>,
    rotate_name: Option<&str>,
) -> CosmianResult<String> {
    let mut args = vec!["sym", "keys", "set-rotation-policy", "--key-id", key_id];
    let interval_str = interval.to_string();
    args.extend(["--interval", &interval_str]);
    let offset_str;
    if let Some(o) = offset {
        offset_str = o.to_string();
        args.extend(["--offset", &offset_str]);
    }
    if let Some(name) = rotate_name {
        args.extend(["--rotation-name", name]);
    }
    run_ckms(cli_conf_path, &args)
}

/// Get the rotation policy for a symmetric key via the CLI.
pub(crate) fn get_rotation_policy(cli_conf_path: &str, key_id: &str) -> CosmianResult<String> {
    let args = vec!["sym", "keys", "get-rotation-policy", "--key-id", key_id];
    run_ckms(cli_conf_path, &args)
}

#[tokio::test]
pub(crate) async fn test_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Set rotation policy with interval, offset, and name
    let output = set_rotation_policy(
        &owner_client_conf_path,
        &key_id,
        86400,
        Some(3600),
        Some("test-keyset"),
    )?;
    assert!(output.contains("Rotation policy set successfully"));

    // Get rotation policy and verify
    let output = get_rotation_policy(&owner_client_conf_path, &key_id)?;
    assert!(
        output.contains("86400"),
        "expected interval=86400 in: {output}"
    );
    assert!(output.contains("3600"), "expected offset=3600 in: {output}");
    assert!(
        output.contains("test-keyset"),
        "expected name=test-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_rotation_policy_name_rejects_at() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Try to set rotation policy with a name containing '@' — should fail
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--interval",
        "86400",
        "--rotation-name",
        "bad@name",
    ];
    let stderr = run_ckms_expect_error(&owner_client_conf_path, &args)?;
    assert!(
        stderr.contains('@'),
        "expected error mentioning '@' in: {stderr}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_rotation_policy_interval_only() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Set rotation policy with interval only (no offset, no name)
    let output = set_rotation_policy(&owner_client_conf_path, &key_id, 43200, None, None)?;
    assert!(output.contains("Rotation policy set successfully"));

    // Get rotation policy and verify
    let output = get_rotation_policy(&owner_client_conf_path, &key_id)?;
    assert!(
        output.contains("43200"),
        "expected interval=43200 in: {output}"
    );
    assert!(
        output.contains("not set") || !output.contains("offset"),
        "expected no offset set"
    );

    Ok(())
}

/// Full keyset workflow: create → set name → encrypt → rekey → decrypt via keyset name
#[tokio::test]
pub(crate) async fn test_keyset_workflow() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create AES-256 key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Set rotation name (keyset) without interval
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "e2e-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(output.contains("Rotation policy set successfully"));

    // Encrypt a file using the keyset bare name
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"hello keyset rotation")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "e2e-keyset",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey: gen-0 → gen-1
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Decrypt via keyset bare name (should walk chain and find gen-0)
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "e2e-keyset",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"hello keyset rotation");

    Ok(())
}

/// Attempting to re-key a non-latest keyset member is rejected
#[tokio::test]
pub(crate) async fn test_rekey_non_latest_rejected() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create AES-256 key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Set rotation name (keyset) without interval
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "e2e-nlat",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // ReKey: gen-0 → gen-1
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Attempt to re-key the original (now non-latest) key — should fail
    let args = vec!["sym", "keys", "re-key", "--key-id", &key_id];
    let stderr = run_ckms_expect_error(&owner_client_conf_path, &args)?;
    assert!(
        stderr.contains("not the latest"),
        "expected 'not the latest' error, got: {stderr}"
    );

    Ok(())
}

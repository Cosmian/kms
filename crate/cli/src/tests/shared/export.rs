use std::process::Command;

use assert_cmd::prelude::*;
use tempfile::TempDir;

use crate::{
    actions::shared::utils::{read_bytes_from_file, read_key_from_file},
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
        },
        elliptic_curve::create_key_pair::create_ec_key_pair,
        symmetric::create_key::create_symmetric_key,
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

pub async fn export(
    sub_command: &str,
    key_id: &str,
    key_file: &str,
    bytes: bool,
    unwrap: bool,
    wrap_key_id: Option<String>,
    allow_revoked: bool,
) -> Result<(), CliError> {
    let mut args: Vec<String> = vec!["keys", "export", key_id, key_file]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if bytes {
        args.push("--bytes".to_owned());
    }
    if unwrap {
        args.push("--unwrap".to_owned());
    }
    if let Some(wrap_key_id) = wrap_key_id {
        args.push("--wrap-key-id".to_owned());
        args.push(wrap_key_id);
    }
    if allow_revoked {
        args.push("--allow-revoked".to_owned());
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_export_cover_crypt() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    // Export
    export(
        "cc",
        &master_private_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;
    export(
        "cc",
        &master_public_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    // generate a user key
    let user_key_id = create_user_decryption_key(
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    )
    .await?;
    export(
        "cc",
        &user_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    Ok(())
}

#[tokio::test]
pub async fn test_export_ec() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a new key pair
    let (private_key_id, public_key_id) = create_ec_key_pair().await?;
    // Export
    export(
        "ec",
        &private_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;
    export(
        "ec",
        &public_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    Ok(())
}

#[tokio::test]
pub async fn test_export_sym() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a symmetric key
    let key_id = create_symmetric_key(None, None, None).await?;
    // Export
    export(
        "sym",
        &key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    Ok(())
}

#[tokio::test]
pub async fn test_export_sym_allow_revoked() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a symmetric key
    let key_id = create_symmetric_key(None, None, None).await?;
    // Export
    export(
        "sym",
        &key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        true,
    )
    .await?;

    Ok(())
}

#[tokio::test]
pub async fn test_export_error_cover_crypt() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // key does not exist
    export(
        "cc",
        "does_not_exist",
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await
    .err()
    .unwrap();

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;

    // Export to non existing dir
    export(
        "cc",
        &master_private_key_id,
        "/does_not_exist/output.export",
        false,
        false,
        None,
        false,
    )
    .await
    .err()
    .unwrap();

    Ok(())
}

#[tokio::test]
pub async fn test_export_bytes_cover_crypt() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    // Export
    export(
        "cc",
        &master_private_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    // read the bytes from the exported file
    let object = read_key_from_file(&tmp_path.join("output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?.to_owned();

    // Export the bytes only
    export(
        "cc",
        &master_private_key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        true,
        false,
        None,
        false,
    )
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;

    assert_eq!(key_bytes, bytes);

    Ok(())
}

#[tokio::test]
pub async fn test_export_bytes_ec() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a new key pair
    let (private_key_id, _public_key_id) = create_ec_key_pair().await?;
    // Export
    export(
        "ec",
        &private_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    // read the bytes from the exported file
    let object = read_key_from_file(&tmp_path.join("output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?.to_owned();

    // Export the bytes only
    export(
        "ec",
        &private_key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        true,
        false,
        None,
        false,
    )
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;

    assert_eq!(key_bytes, bytes);

    Ok(())
}

#[tokio::test]
pub async fn test_export_bytes_sym() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // generate a symmetric key
    let key_id = create_symmetric_key(None, None, None).await?;
    // Export
    export(
        "sym",
        &key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    // read the bytes from the exported file
    let object = read_key_from_file(&tmp_path.join("output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?.to_owned();

    // Export the bytes only
    export(
        "sym",
        &key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        true,
        false,
        None,
        false,
    )
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;

    assert_eq!(key_bytes, bytes);

    Ok(())
}

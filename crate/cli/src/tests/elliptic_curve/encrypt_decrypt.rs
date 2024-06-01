use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_bytes_from_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use predicates::prelude::*;
use tempfile::TempDir;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{
        elliptic_curve::create_key_pair::create_ec_key_pair, utils::recover_cmd_logs, PROG_NAME,
    },
};

/// Encrypts a file using the given public key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    public_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt"];
    args.append(&mut input_files.to_vec());
    args.push("--key-id");
    args.push(public_key_id);

    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "The encrypted file is available at",
    ));
    Ok(())
}

/// Decrypt a file using the given private key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", input_file, "--key-id", private_key_id];
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_encrypt_decrypt_using_ids() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[], false)?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_using_tags() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (_private_key_id, _public_key_id) =
        create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &["tag_ec"], false)?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        "[\"tag_ec\"]",
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        "[\"tag_ec\"]",
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

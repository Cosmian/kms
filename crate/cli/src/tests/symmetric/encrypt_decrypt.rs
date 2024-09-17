use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_bytes_from_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs, PROG_NAME},
};

/// Encrypts a file using the given symmetric key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    symmetric_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt", input_file, "--key-id", symmetric_key_id];
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

/// Decrypt a file using the given symmetric key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    symmetric_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", input_file, "--key-id", symmetric_key_id];
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
async fn test_encrypt_decrypt_with_ids() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    run_encrypt_decrypt_test(&ctx.owner_client_conf_path, &key_id)
}

pub(crate) fn run_encrypt_decrypt_test(cli_conf_path: &str, key_id: &str) -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )))
    }

    encrypt(
        cli_conf_path,
        input_file.to_str().unwrap(),
        key_id,
        Some(output_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        cli_conf_path,
        output_file.to_str().unwrap(),
        key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    if !recovered_file.exists() {
        return Err(CliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )))
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )))
    }

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_with_tags() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;
    let _key_id =
        create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &["tag_sym"])?;

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )))
    }

    encrypt(
        &ctx.owner_client_conf_path,
        input_file.to_str().unwrap(),
        "[\"tag_sym\"]",
        Some(output_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        "[\"tag_sym\"]",
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    if !recovered_file.exists() {
        return Err(CliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )))
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )))
    }

    Ok(())
}

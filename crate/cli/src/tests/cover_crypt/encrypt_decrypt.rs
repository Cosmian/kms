use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

use crate::{
    actions::shared::utils::read_bytes_from_file,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key, SUB_COMMAND,
        },
        utils::{init_test_server, ONCE},
        PROG_NAME,
    },
};

/// Encrypts a file using the given public key and access policy.
pub fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    public_key_id: &str,
    access_policy: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args = vec!["encrypt", input_file, public_key_id, access_policy];
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    cmd.assert().success().stdout(predicate::str::contains(
        "The encrypted file is available at",
    ));
    Ok(())
}

/// Decrypt a file using the given private key
pub fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args = vec!["decrypt", input_file, private_key_id];
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_encrypt_decrypt() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;

    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // create a user decryption key
    let user_ok_key_id = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        &user_ok_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    // this user key should not be able to decrypt the file
    let user_ko_key_id = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "Department::FIN && Security Level::Top Secret",
    )?;
    assert!(
        decrypt(
            &ctx.owner_cli_conf_path,
            output_file.to_str().unwrap(),
            &user_ko_key_id,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}

use std::process::Command;

use assert_cmd::prelude::*;

use super::SUB_COMMAND;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        utils::{extract_uids::extract_user_key, init_test_server, ONCE},
        PROG_NAME,
    },
};

pub fn create_user_decryption_key(
    cli_conf_path: &str,
    master_private_key_id: &str,
    access_policy: &str,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-user-key",
        master_private_key_id,
        access_policy,
    ]);

    let output = cmd.output()?;
    if output.status.success() {
        let user_key_output = std::str::from_utf8(&output.stdout)?;
        return Ok(extract_user_key(user_key_output)
            .ok_or_else(|| CliError::Default("failed extracting the user key".to_owned()))?
            .to_owned())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_user_decryption_key() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, _) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;

    // and a user key
    let user_key_id = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    )?;
    assert!(!user_key_id.is_empty());

    Ok(())
}

#[tokio::test]
pub async fn test_user_decryption_key_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, _) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;

    // bad attributes
    let err = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("attribute not found: Security Level::Top SecretZZZZZZ")
    );

    // bad master private key
    let err = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        "BAD_KEY",
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("Item not found: BAD_KEY"));
    Ok(())
}

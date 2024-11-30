use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        utils::{extract_uids::extract_user_key, recover_cmd_logs},
        PROG_NAME,
    },
};

pub(crate) fn create_user_decryption_key(
    cli_conf_path: &str,
    master_private_key_id: &str,
    access_policy: &str,
    tags: &[&str],
    sensitive: bool,
) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "keys",
        "create-user-key",
        master_private_key_id,
        access_policy,
    ];
    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    if sensitive {
        args.push("--sensitive");
    }
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
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
pub(crate) async fn test_user_decryption_key() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_private_key_id, _) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
        false,
    )?;

    // and a user key
    let user_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;
    assert!(!user_key_id.is_empty());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_user_decryption_key_error() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_private_key_id, _) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
        false,
    )?;

    // bad attributes
    let err = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
        &[],
        false,
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("attribute not found: Security Level::Top SecretZZZZZZ")
    );

    // bad master private key
    let err = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        "BAD_KEY",
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
        &[],
        false,
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("no Covercrypt master private key found for: BAD_KEY")
    );
    Ok(())
}

use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            cover_crypt::master_key_pair::create_cc_master_key_pair,
            utils::{extract_uids::extract_user_key, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

pub(crate) fn create_user_decryption_key(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    access_policy: &str,
    tags: &[&str],
    sensitive: bool,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "keys",
        "create-user-key",
        master_secret_key_id,
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
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let user_key_output = std::str::from_utf8(&output.stdout)?;
        return Ok(extract_user_key(user_key_output)
            .ok_or_else(|| CosmianError::Default("failed extracting the user key".to_owned()))?
            .to_owned());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_user_decryption_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (master_secret_key_id, _) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;

    // and a user key
    let user_key_id = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;
    assert!(!user_key_id.is_empty());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_user_decryption_key_error() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (master_secret_key_id, _) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;

    // bad attributes
    let err = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
        &[],
        false,
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("attribute not found: Top SecretZZZZZZ")
    );

    // bad master secret key
    let err = create_user_decryption_key(
        &owner_client_conf_path,
        "BAD_KEY",
        "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ",
        &[],
        false,
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("no Covercrypt master secret key found for: BAD_KEY")
    );
    Ok(())
}

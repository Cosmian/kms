use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME, save_kms_cli_config, symmetric::create_key::create_symmetric_key,
        utils::recover_cmd_logs,
    },
};

/// Set an attribute on a KMS object via the ckms binary.
fn set_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["set".to_owned(), "--id".to_owned(), key_id.to_owned()];
    args.extend(extra_args.iter().map(|s| (*s).to_owned()));
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Modify an attribute on a KMS object via the ckms binary.
fn modify_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["modify".to_owned(), "--id".to_owned(), key_id.to_owned()];
    args.extend(extra_args.iter().map(|s| (*s).to_owned()));
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_modify_attribute() -> CosmianResult<()> {
    use cosmian_kms_cli_actions::actions::symmetric::keys::create_key::CreateKeyAction;

    let ctx = start_default_test_kms_server().await;
    let (owner_conf, _user_conf) = save_kms_cli_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_conf, CreateKeyAction::default())?;

    // Set cryptographic length (state-independent attribute)
    set_attribute(&owner_conf, &key_id, &["--cryptographic-length", "128"])?;

    // Modify cryptographic length
    modify_attribute(&owner_conf, &key_id, &["--cryptographic-length", "256"])?;

    Ok(())
}

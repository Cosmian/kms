use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME, save_kms_cli_config,
        utils::{extract_uids::extract_uid, recover_cmd_logs},
    },
};

/// Create an FPE key via the CLI and return its unique identifier.
pub(crate) fn create_fpe_key(cli_conf_path: &str, tags: &[&str]) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys".to_owned(), "create".to_owned()];
    for tag in tags {
        args.push("--tag".to_owned());
        args.push((*tag).to_owned());
    }

    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        let uid = extract_uid(stdout, "Unique identifier").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(uid.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_create_fpe_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let uid = create_fpe_key(&owner_client_conf_path, &[])?;
    assert!(!uid.is_empty());

    // Create with a custom tag
    let uid_tagged = create_fpe_key(&owner_client_conf_path, &["my-fpe-key"])?;
    assert!(!uid_tagged.is_empty());
    assert_ne!(uid, uid_tagged);

    Ok(())
}

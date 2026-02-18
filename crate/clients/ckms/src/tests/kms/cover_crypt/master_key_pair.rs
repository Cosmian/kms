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
            utils::{
                extract_uids::{extract_private_key, extract_public_key},
                recover_cmd_logs,
            },
        },
        save_kms_cli_config,
    },
};

pub(crate) fn create_cc_master_key_pair(
    cli_conf_path: &str,
    policy_option: &str,
    file: &str,
    tags: &[&str],
    sensitive: bool,
) -> CosmianResult<(String, String)> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "create-master-key-pair", policy_option, file];
    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    // add sensitive
    if sensitive {
        args.push("--sensitive");
    }
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let master_keys_output = std::str::from_utf8(&output.stdout)?;
        assert!(master_keys_output.contains("Private key unique identifier: "));
        assert!(master_keys_output.contains("Public key unique identifier: "));
        let master_secret_key_id = extract_private_key(master_keys_output)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the master secret key".to_owned())
            })?
            .to_owned();
        let master_public_key_id = extract_public_key(master_keys_output)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the master public key".to_owned())
            })?
            .to_owned();
        return Ok((master_secret_key_id, master_public_key_id));
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_create_master_key_pair() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    Ok(())
}

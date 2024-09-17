use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{
        utils::{
            extract_uids::{extract_private_key, extract_public_key},
            recover_cmd_logs,
        },
        PROG_NAME,
    },
};

pub(crate) fn create_rsa_4096_bits_key_pair(
    cli_conf_path: &str,
    tags: &[&str],
) -> CliResult<(String, String)> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "create"];
    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let rsa_output = std::str::from_utf8(&output.stdout)?;
        assert!(rsa_output.contains("Private key unique identifier:"));
        assert!(rsa_output.contains("Public key unique identifier:"));
        let private_key_id = extract_private_key(rsa_output)
            .ok_or_else(|| CliError::Default("failed extracting the private key".to_owned()))?
            .to_owned();
        let public_key_id = extract_public_key(rsa_output)
            .ok_or_else(|| CliError::Default("failed extracting the public key".to_owned()))?
            .to_owned();
        return Ok((private_key_id, public_key_id))
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_rsa_create_key_pair() -> CliResult<()> {
    // from specs
    let ctx = start_default_test_kms_server().await;
    create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &["tag1", "tag2"])?;
    Ok(())
}

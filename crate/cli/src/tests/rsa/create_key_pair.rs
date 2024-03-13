use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;

use super::SUB_COMMAND;
use crate::{
    error::CliError,
    tests::{
        utils::{
            extract_uids::{extract_private_key, extract_public_key},
            recover_cmd_logs, start_default_test_kms_server, ONCE,
        },
        PROG_NAME,
    },
};

pub fn create_rsa_4096_bits_key_pair(
    cli_conf_path: &str,
    tags: &[&str],
) -> Result<(String, String), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
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
        assert!(rsa_output.contains("Public key unique identifier :"));
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
pub async fn test_rsa_create_key_pair() -> Result<(), CliError> {
    // log_init("trace");

    // from specs
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    create_rsa_4096_bits_key_pair(&ctx.owner_cli_conf_path, &["tag1", "tag2"])?;
    Ok(())
}

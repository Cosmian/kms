use std::process::Command;

use assert_cmd::prelude::*;

use super::SUB_COMMAND;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        utils::{
            extract_uids::{extract_private_key, extract_public_key},
            init_test_server, ONCE,
        },
        PROG_NAME,
    },
};

pub fn create_ec_key_pair(cli_conf_path: &str) -> Result<(String, String), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["keys", "create"]);

    let output = cmd.output()?;
    if output.status.success() {
        let master_keys_output = std::str::from_utf8(&output.stdout)?;
        assert!(master_keys_output.contains("Private key unique identifier:"));
        assert!(master_keys_output.contains("Public key unique identifier :"));
        let master_private_key_id = extract_private_key(master_keys_output)
            .ok_or_else(|| {
                CliError::Default("failed extracting the master private key".to_owned())
            })?
            .to_owned();
        let master_public_key_id = extract_public_key(master_keys_output)
            .ok_or_else(|| CliError::Default("failed extracting the master public key".to_owned()))?
            .to_owned();
        return Ok((master_private_key_id, master_public_key_id))
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_create_key_pair() -> Result<(), CliError> {
    // from specs
    let ctx = ONCE.get_or_init(init_test_server).await;
    create_ec_key_pair(&ctx.cli_conf_path)?;
    Ok(())
}

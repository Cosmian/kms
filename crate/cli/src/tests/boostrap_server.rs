use std::process::Command;

use assert_cmd::prelude::*;

use super::PROG_NAME;
use crate::{
    config::KMS_CLI_CONF_ENV, error::CliError, tests::utils::start_test_server_with_options,
};

pub(crate) const SUB_COMMAND: &str = "bootstrap-start";

#[tokio::test]
pub async fn test_bootstrap_server() -> Result<(), CliError> {
    // init the test server
    // since we are going to rewrite the conf, use a different port
    let ctx = start_test_server_with_options(29997, false, false, false, false, true).await;

    let mut args: Vec<&str> = vec![];
    // No database parameters are supplied, start should fail
    assert!(run_bootstrap_start(&ctx.owner_cli_conf_path, &args).is_err());

    // The database type is not supplied, start should fail
    args.extend_from_slice(&["--sqlite-path", "./sqlite-data"]);
    assert!(run_bootstrap_start(&ctx.owner_cli_conf_path, &args).is_err());

    // The database type is supplied, start should succeed (in HTTP mode)
    args.extend_from_slice(&["--database-type", "sqlite"]);
    assert!(run_bootstrap_start(&ctx.owner_cli_conf_path, &args).is_ok());

    // The PKCS12 password is not supplied: start should fail
    let mut args: Vec<&str> = vec![
        "--https-p12-file",
        "test_data/certificates/kmserver.acme.com.p12",
    ];
    assert!(run_bootstrap_start(&ctx.owner_cli_conf_path, &args).is_err());

    // The PKCS12 password is supplied start should succeed (in HTTPS mode)
    args.extend_from_slice(&["--https-p12-password", "password"]);
    assert!(run_bootstrap_start(&ctx.owner_cli_conf_path, &args).is_ok());

    Ok(())
}

fn run_bootstrap_start(cli_conf_path: &str, args: &[&str]) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return Ok(output.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

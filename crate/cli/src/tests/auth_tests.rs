use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_test_server_with_options;

use super::utils::recover_cmd_logs;
use crate::{
    error::result::CliResult,
    tests::{access::SUB_COMMAND, PROG_NAME},
};

fn run_cli_command(owner_client_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

#[tokio::test]
pub(crate) async fn test_all_authentications() -> CliResult<()> {
    // let us not make other test cases fail
    const PORT: u16 = 9999;
    // plaintext no auth
    let ctx = start_test_server_with_options(PORT, false, false, false).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // plaintext token auth
    let ctx = start_test_server_with_options(PORT, true, false, false).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    let ctx = start_test_server_with_options(PORT, true, true, false).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls client cert auth
    let ctx = start_test_server_with_options(PORT, false, true, true).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    Ok(())
}

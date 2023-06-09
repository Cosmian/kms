use std::process::Command;

use assert_cmd::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{access::SUB_COMMAND, utils::init_test_server_options, PROG_NAME},
};

fn run_cli_command(owner_cli_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    cmd.assert().success();
}

#[tokio::test]
pub async fn test_all_authentications() -> Result<(), CliError> {
    // let us not make other test cases fail
    const PORT: u16 = 9999;
    // plaintext no auth
    let ctx = init_test_server_options(PORT, false, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // plaintext token auth
    let ctx = init_test_server_options(PORT, true, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // tls token auth
    let ctx = init_test_server_options(PORT, true, true, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // tls client cert auth
    let ctx = init_test_server_options(PORT, false, true, true).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    Ok(())
}

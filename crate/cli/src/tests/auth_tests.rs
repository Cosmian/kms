use std::process::Command;

use assert_cmd::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{permission::SUB_COMMAND, test_utils::init_test_server_options, PROG_NAME},
};

fn run_cli_command() {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, "/tmp/kms_9999.json");
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    cmd.assert().success();
}

#[tokio::test]
pub async fn test_plain_no_authentication() -> Result<(), CliError> {
    // let us not make other test cases fail
    const PORT: u16 = 9999;
    // plaintext no auth
    let server_handle = init_test_server_options(PORT, false, false, false)
        .await
        .unwrap();
    run_cli_command();
    server_handle.stop().await;

    // plaintext token auth
    let server_handle = init_test_server_options(PORT, true, false, false)
        .await
        .unwrap();
    run_cli_command();
    server_handle.stop().await;

    // tls client cert auth
    let server_handle = init_test_server_options(PORT, false, true, true)
        .await
        .unwrap();
    run_cli_command();
    server_handle.stop().await;

    // tls token auth
    let server_handle = init_test_server_options(PORT, true, true, false)
        .await
        .unwrap();
    run_cli_command();
    server_handle.stop().await;

    Ok(())
}

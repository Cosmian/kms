use std::process::Command;

use assert_cmd::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        test_utils::{init_test_server_options, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

#[tokio::test]
pub async fn test_client_cert_authentication() -> Result<(), CliError> {
    ONCE.get_or_init(|| init_test_server_options(false, true, true))
        .await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["permission", "owned"]);
    cmd.assert().success();

    Ok(())
}

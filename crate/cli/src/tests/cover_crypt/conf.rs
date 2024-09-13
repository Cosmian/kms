use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use cosmian_logger::log_utils::log_init;
use kms_test_server::{generate_invalid_conf, start_default_test_kms_server};
use predicates::prelude::*;
use tracing::info;

use crate::{
    error::result::CliResult,
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

#[tokio::test]
pub(crate) async fn test_bad_conf() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_bad_conf as backend not sqlite-enc");
        return Ok(());
    }

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_client_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, invalid_conf_path);

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "notfound.json");

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Configuration file \"notfound.json\" specified in KMS_CLI_CONF environment variable does \
         not exist",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;

    cmd.arg("ec").args(vec!["--help"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms.bad");

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("missing field `kms_server_url`"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_group_id_bad() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_secrets_group_id_bad as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms_bad_secret.bad");

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    Ok(())
}

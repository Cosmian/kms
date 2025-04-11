use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_logger::log_init;
use predicates::prelude::*;
use test_kms_server::{generate_invalid_conf, start_default_test_kms_server};
use tracing::info;

use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::result::CosmianResult,
    tests::{
        PROG_NAME,
        kms::{KMS_SUBCOMMAND, utils::recover_cmd_logs},
    },
};

#[tokio::test]
pub(crate) async fn test_bad_conf() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_bad_conf as backend not sqlite-enc");
        return Ok(());
    }

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_client_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, invalid_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, "notfound.toml");

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Configuration file \"notfound.toml\" specified in COSMIAN_CLI_CONF environment variable \
         does not exist",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;

    cmd.arg(KMS_SUBCOMMAND).arg("ec").args(vec!["--help"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(
        COSMIAN_CLI_CONF_ENV,
        "../../test_data/configs/cosmian.bad.toml",
    );

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("missing field `server_url`"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_group_id_bad() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_secrets_group_id_bad as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(
        COSMIAN_CLI_CONF_ENV,
        "../../test_data/configs/kms_bad_secret.bad",
    );

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    Ok(())
}

use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_logger::log_utils::log_init;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        utils::{generate_invalid_conf, recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

#[tokio::test]
pub async fn test_bad_conf() -> Result<(), CliError> {
    log_init("cosmian_kms_server=info,cosmian_kms_cli=debug");
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_cli_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, invalid_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "notfound.json");
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Configuration file \"notfound.json\" does not exist",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms.bad");
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("missing field `kms_server_url`"));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_group_id_bad() -> Result<(), CliError> {
    ONCE.get_or_init(start_default_test_kms_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms_bad_secret.bad");
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");

    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    Ok(())
}

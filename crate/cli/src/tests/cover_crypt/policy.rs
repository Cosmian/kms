use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        utils::{recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

#[tokio::test]
async fn test_view_policy() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security Level::<"))
        .stdout(predicate::str::contains("Top Secret::+"))
        .stdout(predicate::str::contains("R&D"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
        "--detailed",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"Security Level\""))
        .stdout(predicate::str::contains("\"Top Secret\""))
        .stdout(predicate::str::contains("\"last_attribute_value\": 7"));

    Ok(())
}

#[tokio::test]
async fn test_create_policy() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "create",
        "-s",
        "test_data/policy_specifications.json",
        "-p",
        "/tmp/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "The binary policy file was generated in \"/tmp/policy.bin\".",
    ));

    Ok(())
}

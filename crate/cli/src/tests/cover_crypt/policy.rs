use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        utils::{init_test_server, ONCE},
        PROG_NAME,
    },
};

#[tokio::test]
async fn test_view_policy() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security Level::+"))
        .stdout(predicate::str::contains("Top Secret::+"))
        .stdout(predicate::str::contains("R&D"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
        "--detailed",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"Security Level\""))
        .stdout(predicate::str::contains("\"Top Secret\""))
        .stdout(predicate::str::contains("\"last_attribute_value\": 7"));

    Ok(())
}

#[tokio::test]
async fn test_create_policy() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "create",
        "-s",
        "test_data/policy_specifications.json",
        "-p",
        "/tmp/policy.bin",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The binary policy file was generated in \"/tmp/policy.bin\".",
    ));

    Ok(())
}

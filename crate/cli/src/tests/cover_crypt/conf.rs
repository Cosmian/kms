use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        test_utils::{init_test_server, ONCE},
        CONF_PATH_BAD_KEY, PROG_NAME,
    },
};

#[tokio::test]
pub async fn test_bad_conf() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH_BAD_KEY);
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Database secret is wrong"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "notfound.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Bad authorization token"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    cmd.assert().success();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.bad");
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "ERROR: Config JSON malformed reading \"test_data/kms.bad\"",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_group_id_bad() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    #[cfg(feature = "staging")]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_group_id-staging.bad");
    #[cfg(not(feature = "staging"))]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_group_id.bad");

    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unable to open database file"));

    Ok(())
}

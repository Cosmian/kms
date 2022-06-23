use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    tests::{
        test_utils::{init_test_server, ONCE},
        CONF_PATH, CONF_PATH_BAD_KEY, PROG_NAME,
    },
};

#[tokio::test]
pub async fn test_configure() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg("configure");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("New database configured"));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_bad() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    #[cfg(feature = "staging")]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_secret-staging.bad"); // Token can't be deserialized
    #[cfg(not(feature = "staging"))]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_secret.bad"); // Token can't be deserialized

    cmd.arg("abe")
        .args(vec!["init", "--policy", "test_data/policy.json"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Access denied: KmsDatabaseSecret header can't be read",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_group_id_bad() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    #[cfg(feature = "staging")]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_group_id-staging.bad");
    #[cfg(not(feature = "staging"))]
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms_bad_group_id.bad");

    cmd.arg("abe")
        .args(vec!["init", "--policy", "test_data/policy.json"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unable to open database file"));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_key_bad() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg("abe")
        .args(vec!["init", "--policy", "test_data/policy.json"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH_BAD_KEY);

    cmd.arg("abe")
        .args(vec!["init", "--policy", "test_data/policy.json"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Database secret is wrong"));

    Ok(())
}

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    tests::{
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
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

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

const SUB_COMMAND: &str = "trust";

#[tokio::test]
#[cfg_attr(not(feature = "staging"), ignore)]
pub async fn test_quote() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["/tmp"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "You can check all these files manually.",
        ))
        .stdout(predicate::str::contains("Ko").not());

    Ok(())
}

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

const SUB_COMMAND: &str = "trust";

#[tokio::test]
pub async fn test_quote() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["--mr-enclave", "dummy", "/tmp"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "You can check all these files manually.",
        ))
        .stdout(predicate::str::contains(
            "... Remote attestation checking Ok",
        ))
        .stdout(predicate::str::contains("... MR signer checking Ok"))
        .stdout(predicate::str::contains("... Quote checking Ok"))
        .stdout(predicate::str::contains("... Date checking Ok "))
        .stdout(predicate::str::contains(
            "... Quote report data (manifest, kms certificates and nonce) checking Ok ",
        ));

    // We do not test: "... MR enclave checking Ok" because we don't know yet how to pass `--mr-enclave` in the CI

    Ok(())
}

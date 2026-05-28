use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use super::utils::owner_config;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

#[tokio::test]
async fn test_discover_versions() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &conf);
    cmd.args(["server", "discover-versions"]);

    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ));
    }

    let stdout = std::str::from_utf8(&output.stdout)?;
    assert!(
        stdout.contains("1.") || stdout.contains("2."),
        "Expected version numbers in output, got: {stdout}"
    );

    Ok(())
}

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
async fn test_rng_retrieve() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &conf);
    cmd.args(["rng", "retrieve", "--length", "32"]);

    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ));
    }

    let stdout = std::str::from_utf8(&output.stdout)?;
    assert!(
        !stdout.is_empty(),
        "Expected random bytes output, got empty"
    );

    Ok(())
}

#[tokio::test]
async fn test_rng_seed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let seed_hex = "00".repeat(16);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &conf);
    cmd.args(["rng", "seed", "--data", &seed_hex]);

    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ));
    }

    Ok(())
}

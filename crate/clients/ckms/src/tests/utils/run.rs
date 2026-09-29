use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;

use super::cmd_logs::recover_cmd_logs;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, ensure_ckms_binary},
};

/// Get a `Command` for the ckms binary, ensuring it's built first.
///
/// Use this instead of `Command::cargo_bin(PROG_NAME)` directly.
pub(crate) fn ckms_bin() -> Command {
    ensure_ckms_binary();
    Command::cargo_bin(PROG_NAME).expect("Failed to find ckms binary")
}

/// Run a ckms command with the given arguments and return stdout on success.
///
/// This is the common pattern for all ckms binary tests:
/// `Command::cargo_bin("ckms")` + env + args + `recover_cmd_logs` + error handling.
pub(crate) fn run_ckms(cli_conf_path: &str, args: &[&str]) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?.to_owned();
        return Ok(stdout);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Run a ckms command expecting failure, return the stderr message.
pub(crate) fn run_ckms_expect_error(cli_conf_path: &str, args: &[&str]) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Err(CosmianError::Default(
            "Expected command to fail but it succeeded".to_owned(),
        ));
    }
    let stderr = std::str::from_utf8(&output.stderr)?.to_owned();
    Ok(stderr)
}

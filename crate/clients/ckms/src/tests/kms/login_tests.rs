//! CLI integration tests for the `ckms login` command.
//!
//! These tests verify the early-exit behavior of `ckms login` without any
//! user interaction or a running Identity Provider.  They do not open a
//! browser window and do not require a KMS server.

use std::{env, fs, process::Command};

use assert_cmd::prelude::*;

use crate::{
    config::CKMS_CONF_ENV,
    tests::{PROG_NAME, kms::utils::recover_cmd_logs},
};

/// `ckms login` must fail immediately with a clear error when the configuration
/// file does not contain an `oauth2_conf` section.
///
/// This exercises the early-return path in `LoginAction::process()`:
/// ```text
/// let login_config = config.http_config.oauth2_conf.as_ref().ok_or_else(|| {
///     KmsCliError::Default("... oauth2_conf ...")
/// })?;
/// ```
///
/// No KMS server is started and no browser window is opened.
#[tokio::test]
pub(crate) async fn test_ckms_login_fails_without_oauth2_conf() {
    // Write a minimal config that has no oauth2_conf.
    let conf_path = env::temp_dir().join("ckms_login_no_oauth2_conf_test.toml");
    fs::write(
        &conf_path,
        r#"
[http_config]
server_url = "http://127.0.0.1:9998"
"#,
    )
    .expect("failed to write test config");

    let mut cmd = Command::cargo_bin(PROG_NAME).expect("ckms binary not found");
    cmd.env(CKMS_CONF_ENV, &conf_path).arg("login");

    let output = recover_cmd_logs(&mut cmd);
    assert!(
        !output.status.success(),
        "ckms login should fail when oauth2_conf is absent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("oauth2_conf"),
        "error message should mention 'oauth2_conf', got: {stderr}"
    );
}

/// `ckms login` with `--help` must succeed and print help text without
/// starting any server or opening a browser.
#[test]
pub(crate) fn test_ckms_login_help() {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("ckms binary not found");
    cmd.arg("login").arg("--help");
    cmd.assert().success();
}

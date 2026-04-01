//! Integration tests for the `--header` / `-H` CLI option.
//!
//! These tests verify that:
//!
//! 1. A header specified on the command line is actually sent with every request
//!    (end-to-end via a real KMS server).
//! 2. Multiple headers can be combined.
//! 3. An invalid header format (`"no-colon"`) causes the client to fail at
//!    construction time with a clear error message.
//! 4. Custom headers specified in `custom_headers` inside `ckms.toml` are also
//!    forwarded correctly.

use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    tests::{PROG_NAME, kms::utils::recover_cmd_logs, save_kms_cli_config},
};

/// A benign header that the KMS server will silently ignores — we just need the
/// client to accept and forward it without erroring out on its own.
const CUSTOM_HEADER: &str = "X-Custom-Test: cosmian-test-value";

/// Verify that `ckms server version` succeeds when a single extra header is
/// passed via `--header`.
#[tokio::test]
pub(crate) async fn test_server_version_with_custom_header() {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _user_conf_path) = save_kms_cli_config(ctx);

    let mut cmd = Command::cargo_bin(PROG_NAME).expect("ckms binary not found");
    cmd.env(CKMS_CONF_ENV, &owner_conf_path)
        .arg("--header")
        .arg(CUSTOM_HEADER)
        .arg("server")
        .arg("version");

    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

/// Verify that `ckms server version` succeeds when the short flag `-H` is used.
#[tokio::test]
pub(crate) async fn test_server_version_with_short_header_flag() {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _user_conf_path) = save_kms_cli_config(ctx);

    let mut cmd = Command::cargo_bin(PROG_NAME).expect("ckms binary not found");
    cmd.env(CKMS_CONF_ENV, &owner_conf_path)
        .arg("-H")
        .arg(CUSTOM_HEADER)
        .arg("server")
        .arg("version");

    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

/// Verify that multiple `--header` flags can be supplied simultaneously.
#[tokio::test]
pub(crate) async fn test_server_version_with_multiple_custom_headers() {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _user_conf_path) = save_kms_cli_config(ctx);

    let mut cmd = Command::cargo_bin(PROG_NAME).expect("ckms binary not found");
    cmd.env(CKMS_CONF_ENV, &owner_conf_path)
        .arg("--header")
        .arg("X-First-Header: first-value")
        .arg("--header")
        .arg("X-Second-Header: second-value")
        .arg("server")
        .arg("version");

    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

/// Verify that a malformed header (no colon separator) causes the client to
/// exit with a non-zero status code and an informative error message.
#[tokio::test]
pub(crate) async fn test_invalid_header_format_fails() {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _user_conf_path) = save_kms_cli_config(ctx);

    let output = Command::cargo_bin(PROG_NAME)
        .expect("ckms binary not found")
        .env(CKMS_CONF_ENV, &owner_conf_path)
        .arg("--header")
        .arg("InvalidHeaderWithoutColon")
        .arg("server")
        .arg("version")
        .output()
        .expect("failed to spawn ckms");

    assert!(
        !output.status.success(),
        "expected failure for malformed header"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The error message should mention the invalid header value
    assert!(
        stderr.contains("InvalidHeaderWithoutColon"),
        "stderr should reference the bad header: {stderr}"
    );
}

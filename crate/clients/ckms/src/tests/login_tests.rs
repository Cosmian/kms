//! CLI integration tests for the `ckms login` command.
//!
//! These tests verify the early-exit behavior of `ckms login` without any
//! user interaction or a running Identity Provider.  They do not open a
//! browser window and do not require a KMS server.

use std::{env, fs};

use assert_cmd::prelude::*;
use cosmian_config_utils::ConfigUtils;
use tempfile::TempDir;

use crate::{
    config::{CKMS_CONF_ENV, ClientConfig},
    tests::utils::{ckms_bin, recover_cmd_logs},
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

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path).arg("login").arg("oauth");

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
    let mut cmd = ckms_bin();
    cmd.arg("login").arg("--help");
    cmd.assert().success();
}

/// `ckms login cosmian` must fail immediately with a clear error when the
/// configuration file does not contain a `cosmian_conf` section.
#[tokio::test]
pub(crate) async fn test_ckms_login_cosmian_fails_without_cosmian_conf() {
    let conf_path = env::temp_dir().join("ckms_login_no_cosmian_conf_test.toml");
    fs::write(
        &conf_path,
        r#"
[http_config]
server_url = "http://127.0.0.1:9998"
"#,
    )
    .expect("failed to write test config");

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path)
        .arg("login")
        .arg("cosmian")
        .arg("--username")
        .arg("admin")
        .arg("--password")
        .arg("change_me");

    let output = recover_cmd_logs(&mut cmd);
    assert!(
        !output.status.success(),
        "ckms login cosmian should fail when cosmian_conf is absent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cosmian_conf"),
        "error message should mention 'cosmian_conf', got: {stderr}"
    );
}

/// `ckms login approle --help` must succeed and print help text without
/// contacting any server.
#[test]
pub(crate) fn test_ckms_login_approle_help() {
    let mut cmd = ckms_bin();
    cmd.arg("login").arg("approle").arg("--help");
    cmd.assert().success();
}

/// `ckms login approle` with an explicit `--secret-id` must fail cleanly (not
/// panic) when the configured KMS server is unreachable, and must surface an
/// AppRole-login error.  Providing `--secret-id` avoids the interactive prompt.
#[tokio::test]
pub(crate) async fn test_ckms_login_approle_fails_when_server_unreachable() {
    let conf_path = env::temp_dir().join("ckms_login_approle_unreachable_test.toml");
    fs::write(
        &conf_path,
        r#"
[http_config]
server_url = "http://127.0.0.1:1"
"#,
    )
    .expect("failed to write test config");

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path)
        .arg("login")
        .arg("approle")
        .arg("--role-id")
        .arg("some-role")
        .arg("--secret-id")
        .arg("some-secret");

    let output = recover_cmd_logs(&mut cmd);
    assert!(
        !output.status.success(),
        "ckms login approle should fail when the server is unreachable"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AppRole login"),
        "error message should mention 'AppRole login', got: {stderr}"
    );
}

/// `ckms login spire --help` must succeed and print help text without
/// contacting any server or SPIRE Agent.
#[test]
pub(crate) fn test_ckms_login_spire_help() {
    let mut cmd = ckms_bin();
    cmd.arg("login").arg("spire").arg("--help");
    cmd.assert().success();
}

/// `ckms login spire` without `--audience` must fail with clap's required argument error.
#[test]
pub(crate) fn test_ckms_login_spire_fails_without_audience() {
    let mut cmd = ckms_bin();
    cmd.arg("login").arg("spire");

    let output = recover_cmd_logs(&mut cmd);
    assert!(
        !output.status.success(),
        "ckms login spire should fail without --audience"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audience"),
        "error message should mention 'audience', got: {stderr}"
    );
}

/// `ckms login spire` with an unreachable SPIRE Agent Workload API must fail cleanly
/// (not panic) with an informative error mentioning the SPIRE Agent.
#[tokio::test]
pub(crate) async fn test_ckms_login_spire_fails_without_reachable_agent() {
    let conf_path = env::temp_dir().join("ckms_login_spire_unreachable_test.toml");
    fs::write(
        &conf_path,
        r#"
[http_config]
server_url = "http://127.0.0.1:9998"
"#,
    )
    .expect("failed to write test config");

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path)
        .env_remove("SPIFFE_ENDPOINT_SOCKET")
        .arg("login")
        .arg("spire")
        .arg("--audience")
        .arg("test-audience");

    let output = recover_cmd_logs(&mut cmd);
    assert!(
        !output.status.success(),
        "ckms login spire should fail when SPIRE Agent is unreachable"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SPIRE Agent"),
        "error message should mention 'SPIRE Agent', got: {stderr}"
    );
}

/// TOML for an `oauth2_conf` whose token endpoint is `token_url`, with an optional refresh token.
fn oauth2_toml(token_url: &str, refresh_token: Option<&str>) -> String {
    let refresh_line = refresh_token
        .map(|rt| format!("refresh_token = \"{rt}\"\n"))
        .unwrap_or_default();
    format!(
        r#"[http_config]
server_url = "http://127.0.0.1:9998"

[http_config.oauth2_conf]
client_id = "cid"
client_secret = "csecret"
authorize_url = "http://127.0.0.1:1/authorize"
token_url = "{token_url}"
scopes = ["openid", "email", "offline_access"]
{refresh_line}"#
    )
}

/// `ckms login oauth --refresh` exchanges the saved refresh token without a browser, saves the
/// returned token and keeps the refresh token when the identity provider does not rotate it.
#[test]
fn test_ckms_login_oauth_refresh_saves_access_token() {
    let mock = test_kms_server::mock_gmail::start();
    let dir = TempDir::new().unwrap();
    let conf_path = dir.path().join("ckms.toml");
    fs::write(
        &conf_path,
        oauth2_toml(&format!("{}/token", mock.base), Some("rt-1")),
    )
    .unwrap();

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path)
        .args(["login", "oauth", "--refresh"]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(output.status.success(), "{output:?}");

    let conf = ClientConfig::from_toml(conf_path.to_str().unwrap()).unwrap();
    assert_eq!(
        conf.kms_config.http_config.access_token.as_deref(),
        Some("mock-token")
    );
    assert_eq!(
        conf.kms_config
            .http_config
            .oauth2_conf
            .and_then(|c| c.refresh_token)
            .as_deref(),
        Some("rt-1")
    );

    let requests = mock.requests.lock().unwrap().clone();
    let [request] = requests.as_slice() else {
        panic!("expected exactly one token request: {requests:?}");
    };
    assert_eq!(request.path, "/token");
    assert!(request.body.contains("grant_type=refresh_token"));
    assert!(request.body.contains("refresh_token=rt-1"));
}

/// `ckms login oauth --refresh` must fail, naming `refresh_token`, when none was saved.
#[test]
fn test_ckms_login_oauth_refresh_fails_without_refresh_token() {
    let dir = TempDir::new().unwrap();
    let conf_path = dir.path().join("ckms.toml");
    fs::write(&conf_path, oauth2_toml("http://127.0.0.1:1/token", None)).unwrap();

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, &conf_path)
        .args(["login", "oauth", "--refresh"]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("needs `refresh_token` in oauth2_conf"),
        "got: {stderr}"
    );
}

//! Offline `ckms google ...` tests through the real binary: both `GoogleCommands::process`
//! dispatch arms run against a local mock of Google's token endpoint and of the Gmail API.

use cosmian_config_utils::ConfigUtils;
use tempfile::TempDir;
use test_kms_server::{
    TestsContext,
    mock_gmail::{self, MockGoogle},
    start_default_test_kms_server,
};

use crate::{
    config::{CKMS_CONF_ENV, ClientConfig},
    tests::utils::{ckms_bin, owner_config, recover_cmd_logs},
};

const USER: &str = "user@example.com";

/// Write the owner client conf with the Gmail API redirected to `mock`.
fn conf_with_mock(ctx: &TestsContext, mock: &MockGoogle, dir: &TempDir) -> String {
    let mut conf = ClientConfig::from_toml(&owner_config(ctx)).unwrap();
    conf.kms_config.gmail_api_conf = Some(mock_gmail::gmail_api_conf(&mock.base, "/token"));
    let path = dir.path().join("ckms.toml");
    let path = path.to_str().unwrap().to_owned();
    conf.to_toml(&path).unwrap();
    path
}

fn run_google(conf_path: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, conf_path);
    cmd.arg("google").args(args);
    recover_cmd_logs(&mut cmd)
}

fn assert_call(mock: &MockGoogle, method: &str, suffix: &str) {
    let requests = mock.requests.lock().unwrap().clone();
    let [token, call] = requests.as_slice() else {
        panic!("expected a token request and one Gmail call: {requests:?}");
    };
    assert_eq!(token.path, "/token");
    assert_eq!(call.method, method);
    assert_eq!(
        call.path.replace("%40", "@"),
        format!("/gmail/v1/users/{USER}{suffix}")
    );
    assert_eq!(call.authorization.as_deref(), Some("Bearer mock-token"));
}

#[tokio::test]
async fn cli_google_identities_list() {
    let ctx = start_default_test_kms_server().await;
    let mock = mock_gmail::start();
    let dir = TempDir::new().unwrap();
    let conf = conf_with_mock(ctx, &mock, &dir);

    let output = run_google(&conf, &["identities", "list", USER]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(r#"{"ok":true}"#),
        "{output:?}"
    );
    assert_call(&mock, "GET", "/settings/cse/identities/");
}

#[tokio::test]
async fn cli_google_key_pairs_list() {
    let ctx = start_default_test_kms_server().await;
    let mock = mock_gmail::start();
    let dir = TempDir::new().unwrap();
    let conf = conf_with_mock(ctx, &mock, &dir);

    let output = run_google(&conf, &["key-pairs", "list", USER]);
    assert!(output.status.success(), "{output:?}");
    assert_call(&mock, "GET", "/settings/cse/keypairs/");
}

#[tokio::test]
async fn cli_google_key_pairs_get_error() {
    let ctx = start_default_test_kms_server().await;
    let mock = mock_gmail::start();
    let dir = TempDir::new().unwrap();
    let conf = conf_with_mock(ctx, &mock, &dir);

    let output = run_google(&conf, &["key-pairs", "get", "--user-id", USER, "fail"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mock failure"),
        "{output:?}"
    );
}

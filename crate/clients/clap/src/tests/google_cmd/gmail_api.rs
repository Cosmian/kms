//! Offline tests of every `google` subcommand that talks to the Gmail API.
//! A local mock plays both Google's token endpoint and the Gmail API, so these tests
//! need no credentials and no network access: they pin the wire contract.

use clap::Parser;
use cosmian_kms_client::{KmsClient, KmsClientConfig};
use test_kms_server::mock_gmail::{self, MockGoogle, RecordedRequest};

use crate::{actions::google::GoogleCommands, error::result::KmsCliResult};

const USER: &str = "user@example.com";
const USERS_PREFIX: &str = "/gmail/v1/users/user@example.com";

fn config_for(mock: &MockGoogle, token_path: &str) -> KmsClientConfig {
    KmsClientConfig {
        gmail_api_conf: Some(mock_gmail::gmail_api_conf(&mock.base, token_path)),
        ..Default::default()
    }
}

async fn run(args: &[&str], config: KmsClientConfig) -> KmsCliResult<()> {
    let command =
        GoogleCommands::try_parse_from(std::iter::once("google").chain(args.iter().copied()))
            .unwrap();
    command
        .process(KmsClient::new_with_config(config).unwrap())
        .await
}

fn recorded(mock: &MockGoogle) -> Vec<RecordedRequest> {
    mock.requests.lock().unwrap().clone()
}

/// Run a successful command and check the token exchange followed by the single Gmail call.
async fn check(args: &[&str], method: &str, suffix: &str, expected_body: &str) {
    let mock = mock_gmail::start();
    run(args, config_for(&mock, "/token")).await.unwrap();

    let requests = recorded(&mock);
    assert_eq!(requests.len(), 2, "{requests:?}");

    let token = &requests[0];
    assert_eq!(token.method, "POST");
    assert_eq!(token.path, "/token");
    assert!(
        token
            .body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"),
        "{}",
        token.body
    );
    assert!(token.body.contains("assertion="), "{}", token.body);

    let call = &requests[1];
    assert_eq!(call.authorization.as_deref(), Some("Bearer mock-token"));
    assert_eq!(call.method, method);
    assert_eq!(
        call.path.replace("%40", "@"),
        format!("{USERS_PREFIX}{suffix}")
    );
    if expected_body.is_empty() {
        assert!(call.body.is_empty(), "{}", call.body);
    } else {
        let actual: serde_json::Value = serde_json::from_str(&call.body).unwrap();
        let expected: serde_json::Value = serde_json::from_str(expected_body).unwrap();
        assert_eq!(actual, expected);
    }
}

fn identity_body(key_pair_id: &str) -> String {
    format!(r#"{{"primaryKeyPairId":"{key_pair_id}","emailAddress":"{USER}"}}"#)
}

#[tokio::test]
async fn key_pairs_get() {
    check(
        &["key-pairs", "get", "--user-id", USER, "kp1"],
        "GET",
        "/settings/cse/keypairs/kp1",
        "",
    )
    .await;
}

#[tokio::test]
async fn key_pairs_list() {
    check(
        &["key-pairs", "list", USER],
        "GET",
        "/settings/cse/keypairs/",
        "",
    )
    .await;
}

#[tokio::test]
async fn key_pairs_enable() {
    check(
        &["key-pairs", "enable", "--user-id", USER, "kp1"],
        "POST",
        "/settings/cse/keypairs/kp1:enable",
        "",
    )
    .await;
}

#[tokio::test]
async fn key_pairs_disable() {
    check(
        &["key-pairs", "disable", "--user-id", USER, "kp1"],
        "POST",
        "/settings/cse/keypairs/kp1:disable",
        "",
    )
    .await;
}

#[tokio::test]
async fn key_pairs_obliterate() {
    check(
        &["key-pairs", "obliterate", "--user-id", USER, "kp1"],
        "POST",
        "/settings/cse/keypairs/kp1:obliterate",
        "",
    )
    .await;
}

#[tokio::test]
async fn identities_get() {
    check(
        &["identities", "get", USER],
        "GET",
        &format!("/settings/cse/identities/{USER}"),
        "",
    )
    .await;
}

#[tokio::test]
async fn identities_list() {
    check(
        &["identities", "list", USER],
        "GET",
        "/settings/cse/identities/",
        "",
    )
    .await;
}

#[tokio::test]
async fn identities_insert() {
    check(
        &["identities", "insert", "--user-id", USER, "kp1"],
        "POST",
        "/settings/cse/identities/",
        &identity_body("kp1"),
    )
    .await;
}

#[tokio::test]
async fn identities_delete() {
    check(
        &["identities", "delete", USER],
        "DELETE",
        &format!("/settings/cse/identities/{USER}"),
        "",
    )
    .await;
}

#[tokio::test]
async fn identities_patch() {
    check(
        &["identities", "patch", "--user-id", USER, "kp1"],
        "PATCH",
        &format!("/settings/cse/identities/{USER}"),
        &identity_body("kp1"),
    )
    .await;
}

#[tokio::test]
async fn gmail_error_json() {
    let mock = mock_gmail::start();
    let err = run(
        &["key-pairs", "get", "--user-id", USER, "fail"],
        config_for(&mock, "/token"),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("mock failure"), "{err}");
}

#[tokio::test]
async fn gmail_error_not_json() {
    let mock = mock_gmail::start();
    run(
        &["key-pairs", "get", "--user-id", USER, "html"],
        config_for(&mock, "/token"),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
async fn token_endpoint_error() {
    let mock = mock_gmail::start();
    let err = run(
        &["key-pairs", "list", USER],
        config_for(&mock, "/token-fail"),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("400") && msg.contains("invalid_grant"),
        "{msg}"
    );
    assert_eq!(recorded(&mock).len(), 1);
}

#[tokio::test]
async fn token_endpoint_not_json() {
    let mock = mock_gmail::start();
    run(
        &["key-pairs", "list", USER],
        config_for(&mock, "/token-notjson"),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
async fn invalid_service_account_pem() {
    let mock = mock_gmail::start();
    let mut config = config_for(&mock, "/token");
    config.gmail_api_conf.as_mut().unwrap().private_key = "garbage".to_owned();
    run(&["key-pairs", "list", USER], config).await.unwrap_err();
    assert!(recorded(&mock).is_empty());
}

#[tokio::test]
async fn missing_gmail_api_conf() {
    let err = run(&["key-pairs", "list", USER], KmsClientConfig::default())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("No gmail_api_conf object"),
        "{err}"
    );
}

use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{write_json_object_to_file, GmailApiConf, KMS_CLI_CONF_ENV};
use kms_test_server::{start_default_test_kms_server, TestsContext};
use serde::Deserialize;
use tempfile::TempDir;
use tracing::trace;

use crate::{
    error::CliError,
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct Identity {
    emailAddress: String,
    primaryKeyPairId: String,
}
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ListIdentitiesResponse {
    cseIdentities: Vec<Identity>,
}

fn list_identities(cli_conf_path: &str, user_id: &str) -> Result<ListIdentitiesResponse, CliError> {
    // List identities
    let args: Vec<String> = ["list", "--user-id", user_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("identities").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        if output.stdout.is_empty() {
            return Ok(ListIdentitiesResponse {
                cseIdentities: vec![],
            });
        }
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<ListIdentitiesResponse>(output)
            .map_err(|e| CliError::Default(format!("{e}")));
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn get_identities(cli_conf_path: &str, user_id: &str) -> Result<Identity, CliError> {
    // Get identities
    let args: Vec<String> = ["get", "--user-id", user_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("identities").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<Identity>(output)
            .map_err(|e| CliError::Default(format!("{e}")))
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn delete_identities(cli_conf_path: &str, user_id: &str) -> Result<(), CliError> {
    // Delete identities
    let args: Vec<String> = ["delete", "--user-id", user_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("identities").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn insert_identities(
    cli_conf_path: &str,
    user_id: &str,
    key_pair_id: &str,
) -> Result<Identity, CliError> {
    // Insert identities
    let args: Vec<String> = ["insert", "--user-id", user_id, key_pair_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("identities").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<Identity>(output)
            .map_err(|e| CliError::Default(format!("{e}")))
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn create_gmail_api_conf(ctx: &TestsContext) -> Result<String, CliError> {
    // New configuration path with Gmail API configuration
    let owner_client_conf_path = TempDir::new()?.path().join("kms_gmail_api_conf.json");
    std::fs::create_dir_all(owner_client_conf_path.parent().unwrap())?;

    // Override default client configuration
    let service_account_private_key = std::env::var("GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY").expect(
        "GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY undefined. This environment variable MUST be declared \
         as follow: \n\nexport GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----
MIIE...
...
Tysd08+GiFbz0eQpsKcb2XE=
-----END PRIVATE KEY-----\"\n\n",
    );

    let mut new_conf = ctx.owner_client_conf.clone();
    let gmail_api_conf = GmailApiConf {
    account_type : "service_account".to_string(),
    project_id:"bright-arc-384008".to_string(),
    private_key_id:"d0edb1d1bfb2fe5f5d9415f651ed817dc262ec39".to_string(),
    private_key: service_account_private_key,
    client_email:
        "cse-for-gmail@bright-arc-384008.iam.gserviceaccount.com".to_string(),
    client_id:"11451932203930748464".to_string(),
    auth_uri:"https://accounts.google.com/o/oauth2/auth".to_string(),
    token_uri:"https://oauth2.googleapis.com/token".to_string(),
    auth_provider_x509_cert_url:
        "https://www.googleapis.com/oauth2/v1/certs".to_string(),
    client_x509_cert_url:"https://www.googleapis.com/robot/v1/metadata/x509/cse-for-gmail%40bright-arc-384008.iam.gserviceaccount.com".to_string(),
    universe_domain:"googleapis.com".to_string(),
    };
    new_conf.gmail_api_conf = Some(gmail_api_conf);

    write_json_object_to_file(&new_conf, &owner_client_conf_path)
        .expect("Can't write the new conf");

    Ok(owner_client_conf_path.to_str().unwrap().to_string())
}

#[tokio::test]
#[ignore] // This test is ignored because it requires a Gmail test user (not blue nor red users)
async fn test_google_identities() -> Result<(), CliError> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let user_id = "blue@cosmian.com";

    // Override the owner client conf path
    let owner_client_conf_path = create_gmail_api_conf(ctx)?;
    // Read the content of the owner client conf file
    let conf_content = std::fs::read_to_string(&owner_client_conf_path)?;
    trace!("{conf_content}");

    // Fetch and list identities and compare them
    let listed_identities = list_identities(&owner_client_conf_path, user_id)?;
    assert!(listed_identities.cseIdentities.len() == 1);
    assert!(listed_identities.cseIdentities[0].emailAddress == user_id);
    let fetched_identity = get_identities(&owner_client_conf_path, user_id)?;
    assert!(fetched_identity.emailAddress == user_id);
    assert!(
        listed_identities.cseIdentities[0].primaryKeyPairId == fetched_identity.primaryKeyPairId
    );

    // Delete an identity and insert it back
    let key_pair_id = fetched_identity.primaryKeyPairId;
    assert!(delete_identities(&owner_client_conf_path, user_id).is_ok());
    assert!(get_identities(&owner_client_conf_path, user_id).is_err());
    let inserted_identity = insert_identities(&owner_client_conf_path, user_id, &key_pair_id)?;
    assert!(inserted_identity.primaryKeyPairId == key_pair_id);
    Ok(())
}

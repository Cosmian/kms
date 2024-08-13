use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use serde::Deserialize;

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
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<ListIdentitiesResponse>(output)
            .map_err(|e| CliError::Default(format!("{e}")))
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

#[tokio::test]
pub async fn test_google_identities() -> Result<(), CliError> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let user_id = "blue@cosmian.com";

    // Fetch and list identities and compare them
    let listed_identities = list_identities(&ctx.owner_client_conf_path, user_id)?;
    assert!(listed_identities.cseIdentities.len() == 1);
    assert!(listed_identities.cseIdentities[0].emailAddress == user_id);
    let fetched_identity = get_identities(&ctx.owner_client_conf_path, user_id)?;
    assert!(fetched_identity.emailAddress == user_id);
    assert!(
        listed_identities.cseIdentities[0].primaryKeyPairId == fetched_identity.primaryKeyPairId
    );
    let key_pair_id = fetched_identity.primaryKeyPairId;

    // Delete an identity and insert it back
    assert!(delete_identities(&ctx.owner_client_conf_path, user_id).is_ok());
    assert!(get_identities(&ctx.owner_client_conf_path, user_id).is_err());
    let inserted_identity = insert_identities(&ctx.owner_client_conf_path, user_id, &key_pair_id)?;
    assert!(inserted_identity.primaryKeyPairId == key_pair_id);
    Ok(())
}

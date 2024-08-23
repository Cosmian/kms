use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use serde::Deserialize;

use crate::{
    error::CliError,
    tests::{google_cmd::identities::create_gmail_api_conf, utils::recover_cmd_logs, PROG_NAME},
};

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct KaclsKeyMetadata {
    kaclsUri: String,
    kaclsData: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct PrivateKeyMetaData {
    privateKeyMetadataId: String,
    kaclsKeyMetadata: KaclsKeyMetadata,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct KeyPairs {
    keyPairId: String,
    pem: String,
    subjectEmailAddresses: Vec<String>,
    enablementState: String,
    disableTime: Option<String>,
    privateKeyMetadata: Vec<PrivateKeyMetaData>,
}
#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct ListKeyPairsResponse {
    cseKeyPairs: Vec<KeyPairs>,
}

fn list_keypairs(cli_conf_path: &str, user_id: &str) -> Result<ListKeyPairsResponse, CliError> {
    // List keypairs
    let args: Vec<String> = ["list", "--user-id", user_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("keypairs").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<ListKeyPairsResponse>(output)
            .map_err(|e| CliError::Default(format!("{e}")))
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn get_keypairs(
    cli_conf_path: &str,
    user_id: &str,
    keypair_id: &str,
) -> Result<KeyPairs, CliError> {
    // Get keypairs
    let args: Vec<String> = ["get", "--user-id", user_id, keypair_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("keypairs").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return serde_json::from_str::<KeyPairs>(output)
            .map_err(|e| CliError::Default(format!("{e}")))
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn disable_keypairs(cli_conf_path: &str, user_id: &str, key_pair_id: &str) -> Result<(), CliError> {
    // Disable keypairs
    let args: Vec<String> = ["disable", "--user-id", user_id, key_pair_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("keypairs").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn enable_keypairs(cli_conf_path: &str, user_id: &str, key_pair_id: &str) -> Result<(), CliError> {
    // Enable keypairs
    let args: Vec<String> = ["enable", "--user-id", user_id, key_pair_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("google").arg("keypairs").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
#[ignore] // This test is ignored because it requires a Gmail test user (not blue nor red users)
pub(crate) async fn test_google_keypairs() -> Result<(), CliError> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let user_id = "blue@cosmian.com".to_string();

    // Override the owner client conf path
    let owner_client_conf_path = create_gmail_api_conf(ctx)?;

    // Fetch and list keypairs and compare one of them
    let listed_keypairs = list_keypairs(&owner_client_conf_path, &user_id)?;
    assert!(
        listed_keypairs.cseKeyPairs[0]
            .subjectEmailAddresses
            .contains(&user_id)
    );
    let enabled_key_pair = listed_keypairs
        .cseKeyPairs
        .iter()
        .find(|&item| item.enablementState == "enabled")
        .unwrap();
    let mut fetched_keypair = get_keypairs(
        &owner_client_conf_path,
        &user_id,
        &enabled_key_pair.keyPairId,
    )?;
    assert!(fetched_keypair.subjectEmailAddresses.contains(&user_id));

    // Disable keypair
    assert!(
        disable_keypairs(
            &owner_client_conf_path,
            &user_id,
            &enabled_key_pair.keyPairId
        )
        .is_ok()
    );
    fetched_keypair = get_keypairs(
        &owner_client_conf_path,
        &user_id,
        &enabled_key_pair.keyPairId,
    )?;
    assert!(fetched_keypair.enablementState == "disabled");

    // Enable keypair
    assert!(
        enable_keypairs(
            &owner_client_conf_path,
            &user_id,
            &enabled_key_pair.keyPairId
        )
        .is_ok()
    );
    fetched_keypair = get_keypairs(
        &owner_client_conf_path,
        &user_id,
        &enabled_key_pair.keyPairId,
    )?;
    assert!(fetched_keypair.enablementState == "enabled");
    Ok(())
}

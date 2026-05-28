use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli_actions::{
    actions::{
        mac::{CHashingAlgorithm, MacAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use super::utils::{extract_uids::extract_uid, owner_config, recover_cmd_logs};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, symmetric::create_key::create_symmetric_key},
};

const SUB_COMMAND: &str = "mac";

/// Create a symmetric key via the CLI
pub(crate) fn create_mac(cli_conf_path: &str, action: MacAction) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["--mac-key-id".to_owned(), action.mac_key_id];
    args.extend(vec![
        "--algorithm".to_owned(),
        action.hashing_algorithm.to_string(),
    ]);
    if let Some(data) = action.data {
        args.extend(vec!["--data".to_owned(), data]);
    }
    if let Some(correlation_value) = action.correlation_value {
        args.extend(vec!["--correlation-value".to_owned(), correlation_value]);
    }
    if action.init_indicator {
        args.push("--init-indicator".to_owned());
    }
    if action.final_indicator {
        args.push("--final-indicator".to_owned());
    }

    // Updated for 5.13.0: `mac` now requires a subcommand; use `compute`.
    cmd.arg(SUB_COMMAND).arg("compute").args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Mac output").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_mac() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let large_data = "00".repeat(1024);

    create_mac(
        &owner_client_conf_path,
        MacAction {
            mac_key_id,
            hashing_algorithm: CHashingAlgorithm::SHA3_256,
            data: Some(large_data),
            correlation_value: None,
            init_indicator: false,
            final_indicator: false,
        },
    )?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_sha1() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let data = "00".repeat(64);

    create_mac(
        &owner_client_conf_path,
        MacAction {
            mac_key_id,
            hashing_algorithm: CHashingAlgorithm::SHA1,
            data: Some(data),
            correlation_value: None,
            init_indicator: false,
            final_indicator: false,
        },
    )?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_sha224() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let data = "00".repeat(64);

    create_mac(
        &owner_client_conf_path,
        MacAction {
            mac_key_id,
            hashing_algorithm: CHashingAlgorithm::SHA224,
            data: Some(data),
            correlation_value: None,
            init_indicator: false,
            final_indicator: false,
        },
    )?;

    Ok(())
}

/// Verify a MAC via the CLI
fn verify_mac(
    cli_conf_path: &str,
    mac_key_id: &str,
    algorithm: &str,
    data_hex: &str,
    mac_hex: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args([
        SUB_COMMAND,
        "verify",
        "--mac-key-id",
        mac_key_id,
        "--algorithm",
        algorithm,
        "--data",
        data_hex,
        "--mac",
        mac_hex,
    ]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_mac_verify() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let data_hex = "01".repeat(64);

    // Compute MAC
    let mac_hex = create_mac(
        &owner_client_conf_path,
        MacAction {
            mac_key_id: mac_key_id.clone(),
            hashing_algorithm: CHashingAlgorithm::SHA3_256,
            data: Some(data_hex.clone()),
            correlation_value: None,
            init_indicator: false,
            final_indicator: false,
        },
    )?;

    // Verify MAC
    verify_mac(
        &owner_client_conf_path,
        &mac_key_id,
        "sha3-256",
        &data_hex,
        &mac_hex,
    )?;

    Ok(())
}

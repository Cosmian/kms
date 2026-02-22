use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::{
        mac::{CHashingAlgorithm, MacAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use super::{KMS_SUBCOMMAND, utils::extract_uids::extract_uid};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs},
        save_kms_cli_config,
    },
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
    cmd.arg(KMS_SUBCOMMAND)
        .arg(SUB_COMMAND)
        .arg("compute")
        .args(args);

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
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

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

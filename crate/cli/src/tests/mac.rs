use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{
    reexport::cosmian_kms_ui_utils::create_utils::SymmetricAlgorithm, KMS_CLI_CONF_ENV,
};
use cosmian_logger::log_init;
use kms_test_server::start_default_test_kms_server;

use super::utils::extract_uids::extract_uid;
use crate::{
    actions::{
        mac::{CHashingAlgorithm, MacAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::{result::CliResult, CliError},
    tests::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs, PROG_NAME},
};

const SUB_COMMAND: &str = "mac";

/// Create a symmetric key via the CLI
pub(crate) fn create_mac(cli_conf_path: &str, action: MacAction) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

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

    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Mac output").ok_or_else(|| {
            CliError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_mac() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let mac_key_id = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let large_data = "00".repeat(1024);

    create_mac(
        &ctx.owner_client_conf_path,
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

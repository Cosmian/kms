use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::actions::kms::{hash::HashAction, mac::CHashingAlgorithm};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use super::{KMS_SUBCOMMAND, utils::extract_uids::extract_uid};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, kms::utils::recover_cmd_logs, save_kms_cli_config},
};

const SUB_COMMAND: &str = "hash";

/// Create a symmetric key via the CLI
pub(crate) fn create_hash(cli_conf_path: &str, action: HashAction) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "--algorithm".to_owned(),
        action.hashing_algorithm.to_string(),
    ];
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

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Hash output").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_hash() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    create_hash(
        &owner_client_conf_path,
        HashAction {
            hashing_algorithm: CHashingAlgorithm::SHA3_256,
            data: Some("010203".to_owned()),
            correlation_value: None,
            init_indicator: false,
            final_indicator: false,
        },
    )?;

    Ok(())
}

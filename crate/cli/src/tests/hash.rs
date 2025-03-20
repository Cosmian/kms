use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_logger::log_init;
use kms_test_server::start_default_test_kms_server;

use super::utils::extract_uids::extract_uid;
use crate::{
    actions::{hash::HashAction, mac::CHashingAlgorithm},
    error::{result::CliResult, CliError},
    reexport::cosmian_kms_client::KMS_CLI_CONF_ENV,
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

const SUB_COMMAND: &str = "hash";

/// Create a symmetric key via the CLI
pub(crate) fn create_hash(cli_conf_path: &str, action: HashAction) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

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

    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Hash output").ok_or_else(|| {
            CliError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_hash() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    create_hash(
        &ctx.owner_client_conf_path,
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

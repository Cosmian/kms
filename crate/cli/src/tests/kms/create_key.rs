use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::actions::symmetric::keys::create_key::CreateKeyAction;
use regex::{Regex, RegexBuilder};

use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

//todo(manu): create a test crate
pub(crate) fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"^\s*{pattern}: (?P<uid>.+?)[\s\.]*?$");
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Create a symmetric key via the CLI
pub(crate) fn create_symmetric_key(
    cli_conf_path: &str,
    action: CreateKeyAction,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["sym".to_owned(), "keys".to_owned(), "create".to_owned()];
    let num_s;
    if let Some(number_of_bits) = action.number_of_bits {
        num_s = number_of_bits.to_string();
        args.extend(vec!["--number-of-bits".to_owned(), num_s]);
    }
    if let Some(wrap_key_b64) = action.wrap_key_b64.clone() {
        args.extend(vec!["--bytes-b64".to_owned(), wrap_key_b64]);
    }
    args.extend(vec!["--algorithm".to_owned(), action.algorithm.to_string()]);

    // add tags
    for tag in action.tags {
        args.push("--tag".to_owned());
        args.push(tag);
    }
    if action.sensitive {
        args.push("--sensitive".to_owned());
    }
    if let Some(wrapping_key_id) = action.wrapping_key_id.as_ref() {
        args.extend(vec![
            "--wrapping-key-id".to_owned(),
            wrapping_key_id.to_owned(),
        ]);
    }
    if let Some(key_id) = action.key_id.as_ref() {
        args.push(key_id.to_owned());
    }
    cmd.arg("kms").args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Unique identifier").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_create_symmetric_key() -> CosmianResult<()> {
    // AES 256 bit key
    create_symmetric_key(
        "../../test_data/configs/cosmian.toml",
        CreateKeyAction::default(),
    )?;

    Ok(())
}

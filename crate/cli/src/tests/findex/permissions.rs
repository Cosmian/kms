use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_findex_cli::actions::permissions::{GrantPermission, RevokePermission};
use regex::{Regex, RegexBuilder};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

/// Extract the `key_uid` (prefixed by a pattern) from a text
#[allow(clippy::unwrap_used)]
pub(crate) fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"\[\S+\] {pattern}: (?P<uid>[0-9a-fA-F-]+)");
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

pub(crate) fn create_index_id_cmd(cli_conf_path: &str) -> CosmianResult<Uuid> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let args = vec!["permissions".to_owned(), "create".to_owned()];
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex-server").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;
        trace!("findex_output: {}", findex_output);
        let unique_identifier = extract_uid(
            findex_output,
            "New admin permission successfully created on index",
        )
        .ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        let uuid = Uuid::parse_str(unique_identifier)?;
        return Ok(uuid);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn grant_permission_cmd(
    cli_conf_path: &str,
    action: &GrantPermission,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let args = vec![
        "permissions".to_owned(),
        "grant".to_owned(),
        "--user".to_owned(),
        action.user.clone(),
        "--index-id".to_owned(),
        action.index_id.to_string(),
        "--permission".to_owned(),
        action.permission.to_string(),
    ];
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex-server").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;
        return Ok(findex_output.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn revoke_permission_cmd(
    cli_conf_path: &str,
    action: &RevokePermission,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let args = vec![
        "permissions".to_owned(),
        "revoke".to_owned(),
        "--user".to_owned(),
        action.user.clone(),
        "--index-id".to_owned(),
        action.index_id.to_string(),
    ];
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex-server").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;
        return Ok(findex_output.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

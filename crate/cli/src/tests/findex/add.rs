use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_findex_cli::reexports::cosmian_findex_structs::Uuids;
use tracing::debug;
use uuid::Uuid;

use crate::{
    actions::encrypt_and_index::EncryptAndIndexAction,
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

#[allow(clippy::unwrap_used)]
pub(crate) fn add_cmd(cli_conf_path: &str, action: EncryptAndIndexAction) -> CosmianResult<Uuids> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let mut args = vec![
        "encrypt-and-index".to_owned(),
        "--key".to_owned(),
        action.findex_parameters.key.clone(),
        "--label".to_owned(),
        action.findex_parameters.label,
        "--index-id".to_owned(),
        action.findex_parameters.index_id.to_string(),
        "--csv-path".to_owned(),
        action.csv_path.to_str().unwrap().to_owned(),
        "--data-encryption-algorithm".to_owned(),
        action.data_encryption_algorithm.to_string(),
    ];
    if let Some(key_encryption_key_id) = action.key_encryption_key_id {
        args.push("--kek-id".to_owned());
        args.push(key_encryption_key_id);
    }
    if let Some(data_encryption_key_id) = action.data_encryption_key_id {
        args.push("--dek-id".to_owned());
        args.push(data_encryption_key_id);
    }
    if let Some(nonce) = action.nonce {
        args.push("--nonce".to_owned());
        args.push(nonce);
    }
    if let Some(authentication_data) = action.authentication_data {
        args.push("--authentication_data".to_owned());
        args.push(authentication_data);
    }

    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex-server").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;

        let uuids: Vec<Uuid> = findex_output
            .lines()
            .filter(|line| line.contains("UUID:"))
            .filter_map(|line| {
                line.split("UUID:")
                    .nth(1)
                    .map(|uuid_str| uuid_str.trim().to_owned())
            })
            .map(|uuid| Uuid::parse_str(&uuid).unwrap())
            .collect();
        let uuids = Uuids::from(uuids);
        return Ok(uuids);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

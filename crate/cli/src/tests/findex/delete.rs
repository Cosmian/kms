use std::process::Command;

use assert_cmd::prelude::*;
use tracing::debug;

use crate::{
    actions::delete_datasets::DeleteDatasetAction,
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

// todo(manu): to delete in favor of existing cosmian_findex_cli actions
pub(crate) fn delete_cmd(
    cli_conf_path: &str,
    action: &DeleteDatasetAction,
) -> CosmianResult<String> {
    let mut args = vec![
        "delete-dataset".to_owned(),
        "--index-id".to_owned(),
        action.index_id.to_string(),
    ];
    for uuid in &action.uuid {
        args.push("--uuid".to_owned());
        args.push(uuid.to_string());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
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

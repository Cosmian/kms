use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{
        shared::export_key,
        symmetric::create_key::create_symmetric_key,
        utils::{extract_uids::extract_uid, recover_cmd_logs},
        PROG_NAME,
    },
};

/// Create a symmetric key via the CLI
pub(crate) fn rekey_symmetric_key(
    cli_conf_path: &str,
    unique_identifier: &str,
) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "re-key"];
    args.extend(vec!["--key-id", unique_identifier]);
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Unique identifier").ok_or_else(|| {
            CliError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_rekey_symmetric_key() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;

    // AES 256 bit key
    let id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &id,
        tmp_path.join("aes_sym").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // and refresh it
    let id_2 = rekey_symmetric_key(&ctx.owner_client_conf_path, &id)?;

    assert_eq!(id, id_2);

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &id,
        tmp_path.join("aes_sym_2").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // Compare the symmetric key bytes
    let old_key = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym"))?
        .key_block()?
        .key_bytes()?;
    let new_key = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_2"))?
        .key_block()?
        .key_bytes()?;

    assert_ne!(old_key, new_key);

    Ok(())
}

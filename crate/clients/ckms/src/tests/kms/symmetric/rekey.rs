use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::read_object_from_json_ttlv_file,
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            shared::{ExportKeyParams, export_key},
            symmetric::create_key::create_symmetric_key,
            utils::{extract_uids::extract_uid, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

/// Create a symmetric key via the CLI
pub(crate) fn rekey_symmetric_key(
    cli_conf_path: &str,
    unique_identifier: &str,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    // Ensure sufficient stack for the child process on Windows
    cmd.env("RUST_MIN_STACK", "16777216");

    let mut args = vec!["keys", "re-key"];
    args.extend(vec!["--key-id", unique_identifier]);
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Unique identifier").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

const AES_KEY_SIZE: usize = 256;

#[tokio::test]
pub(crate) async fn test_rekey_symmetric_key() -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // AES 256 bit key
    let id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(AES_KEY_SIZE),
            ..Default::default()
        },
    )?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: id.clone(),
        key_file: tmp_path.join("aes_sym").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // and refresh it
    let id_2 = rekey_symmetric_key(&owner_client_conf_path, &id)?;

    assert_eq!(id, id_2);

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "sym".to_owned(),
        key_id: id,
        key_file: tmp_path.join("aes_sym_2").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // Compare the symmetric key bytes
    let old_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym"))?;
    let new_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_2"))?;
    assert_ne!(
        old_object.key_block()?.key_bytes()?,
        new_object.key_block()?.key_bytes()?
    );

    // Compare the attributes
    assert!(old_object.attributes()? == new_object.attributes()?);
    assert_eq!(
        new_object.attributes()?.cryptographic_length.unwrap(),
        i32::try_from(AES_KEY_SIZE).unwrap()
    );

    Ok(())
}

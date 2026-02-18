use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::{
        secret_data::create_secret::CreateSecretDataAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use cosmian_logger::info;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            symmetric::create_key::create_symmetric_key,
            utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

pub(crate) fn create_secret_data(
    cli_conf_path: &str,
    action: &CreateSecretDataAction,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["secret-data", "create"];

    if let Some(secret_value) = action.secret_value.as_ref() {
        args.push("--value");
        args.push(secret_value);
    }
    // add tags
    for tag in &action.tags {
        args.push("--tag");
        args.push(tag);
    }
    if action.sensitive {
        args.push("--sensitive");
    }
    if let Some(wrapping_key_id) = action.wrapping_key_id.as_ref() {
        args.push("--wrapping-key-id");
        args.push(wrapping_key_id);
    }
    if let Some(secret_id) = action.secret_id.as_ref() {
        args.push(secret_id);
    }
    cmd.arg(KMS_SUBCOMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let secret_data_output = std::str::from_utf8(&output.stdout)?;
        assert!(secret_data_output.contains("The secret data was successfully generated."));
        let secret_data_id = extract_unique_identifier(secret_data_output)
            .ok_or_else(|| CosmianError::Default("failed extracting the private key".to_owned()))?
            .to_owned();
        return Ok(secret_data_id);
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_secret_data() -> CosmianResult<()> {
    // from specs
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            tags: vec!["tag1".to_owned(), "tag2".to_owned()],
            ..Default::default()
        },
    )?;

    let created_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("secret_id".to_owned()),
            tags: vec!["tag1".to_owned(), "tag2".to_owned()],
            ..Default::default()
        },
    )?;
    assert_eq!(created_id, "secret_id".to_owned());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secret_data_with_wrapping() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // First create a symmetric key for wrapping
    let wrapping_key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            tags: vec!["wrapping_key_tag".to_owned()],
            ..Default::default()
        },
    )?;

    // Now create a SecretData object with the wrapping key
    let secret_data_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("wrapped_secret_data".to_owned()),
            tags: vec!["wrapped_secret".to_owned()],
            wrapping_key_id: Some(wrapping_key_id),
            ..Default::default()
        },
    )?;

    assert_eq!(secret_data_id, "wrapped_secret_data".to_owned());

    // Verify that the secret data was created successfully
    // The fact that create_secret_data returned successfully means
    // the server accepted the wrapping_key_id parameter and processed it
    info!("Successfully created SecretData with wrapping key: {secret_data_id}");

    Ok(())
}

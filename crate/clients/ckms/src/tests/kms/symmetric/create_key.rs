use std::process::Command;

use assert_cmd::prelude::*;
use base64::{Engine as _, engine::general_purpose};
use clap::ValueEnum;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::{
        cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
        cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng,
            reexport::rand_core::{RngCore, SeedableRng},
        },
    },
};
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            utils::{extract_uids::extract_uid, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

/// Create a symmetric key via the CLI
pub(crate) fn create_symmetric_key(
    cli_conf_path: &str,
    action: CreateKeyAction,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys".to_owned(), "create".to_owned()];
    let num_s;
    if let Some(number_of_bits) = action.number_of_bits {
        num_s = number_of_bits.to_string();
        args.extend(vec!["--number-of-bits".to_owned(), num_s]);
    }
    if let Some(wrap_key_b64) = action.wrap_key_b64.clone() {
        args.extend(vec!["--bytes-b64".to_owned(), wrap_key_b64]);
    }
    args.extend(vec![
        "--algorithm".to_owned(),
        action
            .algorithm
            .to_possible_value()
            .expect("possible value")
            .get_name()
            .to_string(),
    ]);

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

#[tokio::test]
async fn test_create_symmetric_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; 32];

    // AES
    {
        // AES 256 bit key
        create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;
        // AES 128 bit key
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(128),
                ..Default::default()
            },
        )?;
        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                wrap_key_b64: Some(key_b64),
                ..Default::default()
            },
        )?;
    }

    #[cfg(feature = "non-fips")]
    {
        // ChaCha20 256 bit key
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                algorithm: SymmetricAlgorithm::Chacha20,
                ..Default::default()
            },
        )?;
        // ChaCha20 128 bit key
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(128),
                algorithm: SymmetricAlgorithm::Chacha20,
                ..Default::default()
            },
        )?;
        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                wrap_key_b64: Some(key_b64),
                algorithm: SymmetricAlgorithm::Chacha20,
                ..Default::default()
            },
        )?;
    }

    // Sha3
    {
        // ChaCha20 256 bit salt
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
        // ChaCha20 salts
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(224),
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(256),
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(384),
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                number_of_bits: Some(512),
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
        //  ChaCha20 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0_u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        create_symmetric_key(
            &owner_client_conf_path,
            CreateKeyAction {
                wrap_key_b64: Some(key_b64),
                algorithm: SymmetricAlgorithm::Sha3,
                ..Default::default()
            },
        )?;
    }
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_create_wrapped_symmetric_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let wrapping_key_id =
        create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;
    // AES 128 bit key
    let _wrapped_symmetric_key = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(128),
            wrapping_key_id: Some(wrapping_key_id),
            ..Default::default()
        },
    )?;
    Ok(())
}

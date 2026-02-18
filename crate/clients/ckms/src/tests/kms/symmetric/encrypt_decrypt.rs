use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::symmetric::{
        DecryptAction, EncryptAction, KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction,
    },
    reexport::cosmian_kms_client::{
        read_bytes_from_file,
        reexport::cosmian_kms_client_utils::{
            create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
        },
    },
};
use cosmian_logger::log_init;
use strum::IntoEnumIterator;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND, symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

/// Encrypts a file using the given symmetric key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    symmetric_key_id: &str,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "encrypt".to_owned(),
        input_file.to_owned(),
        "--key-id".to_owned(),
        symmetric_key_id.to_owned(),
        "-d".to_owned(),
        data_encryption_algorithm.to_string(),
    ];
    if let Some(key_encryption_algorithm) = key_encryption_algorithm {
        args.push("-e".to_owned());
        args.push(key_encryption_algorithm.to_string());
    }
    if let Some(output_file) = output_file {
        args.push("-o".to_owned());
        args.push(output_file.to_owned());
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a".to_owned());
        args.push(authentication_data.to_owned());
    }
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Decrypt a file using the given symmetric key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    symmetric_key_id: &str,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "decrypt".to_owned(),
        input_file.to_owned(),
        "--key-id".to_owned(),
        symmetric_key_id.to_owned(),
        "-d".to_owned(),
        data_encryption_algorithm.to_string(),
    ];
    if let Some(key_encryption_algorithm) = key_encryption_algorithm {
        args.push("-e".to_owned());
        args.push(key_encryption_algorithm.to_string());
    }
    if let Some(output_file) = output_file {
        args.push("-o".to_owned());
        args.push(output_file.to_owned());
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a".to_owned());
        args.push(authentication_data.to_owned());
    }
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn run_encrypt_decrypt_test(
    cli_conf_path: &str,
    key_id: &str,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    encryption_overhead: u64,
) -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CosmianError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )));
    }

    encrypt(
        cli_conf_path,
        input_file.to_str().unwrap(),
        key_id,
        data_encryption_algorithm,
        key_encryption_algorithm,
        Some(output_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;

    if encryption_overhead != 0 {
        assert_eq!(
            fs::metadata(output_file.clone())?.len(),
            fs::metadata(input_file.clone())?.len() + encryption_overhead
        );
    }

    // the user key should be able to decrypt the file
    decrypt(
        cli_conf_path,
        output_file.to_str().unwrap(),
        key_id,
        data_encryption_algorithm,
        key_encryption_algorithm,
        Some(recovered_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;
    if !recovered_file.exists() {
        return Err(CosmianError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )));
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CosmianError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )));
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_server_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        None,
        12 /* nonce */  + 16, // tag
    )
}

#[tokio::test]
async fn test_aes_cbc_server_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesCbc,
        None,
        8 /* padding */ + 16, // iv
    )
}

#[tokio::test]
async fn test_aes_xts_server_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(512),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesXts,
        None,
        16, // tweak
    )
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_aes_gcm_siv_server_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcmSiv,
        None,
        12 /* nonce */ + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_chacha20_poly1305_server_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Chacha20,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        12 /* nonce */ + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_encrypt_decrypt_with_tags() -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            tags: vec!["tag_sym".to_owned()],
            ..Default::default()
        },
    )?;

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CosmianError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )));
    }

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        &key_id,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        Some(output_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &key_id,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        Some(recovered_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;
    if !recovered_file.exists() {
        return Err(CosmianError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )));
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CosmianError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )));
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_aes_gcm_client_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let kek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[tokio::test]
async fn test_aes_gcm_aes_xts_client_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let kek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesXts,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 64 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 16, // tweak
    )
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_aes_gcm_chacha20_client_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let kek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[tokio::test]
async fn test_rfc5649_aes_gcm_client_side() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let kek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::RFC5649),
        8 + 32 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */ + 16, // tag
    )
}

#[tokio::test]
async fn test_client_side_encryption_with_buffer() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let kek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let kms_rest_client = ctx.get_owner_client();
    // Generate an ephemeral key (DEK) and wrap it with the KEK.
    let (dek, encapsulation) = EncryptAction::default()
        .server_side_kem_encapsulation(
            kms_rest_client.clone(),
            &kek,
            KeyEncryptionAlgorithm::RFC5649,
            DataEncryptionAlgorithm::AesGcm,
        )
        .await?;

    for size in [0, 1, 16, 64, 256, 1024, 4096, 16384] {
        let plaintext: Vec<u8> = vec![0; size];
        for dea in DataEncryptionAlgorithm::iter() {
            if dea == DataEncryptionAlgorithm::AesXts {
                continue;
            }
            let ciphertext = EncryptAction::default().client_side_encrypt_with_buffer(
                &dek,
                &encapsulation,
                dea,
                None,
                &plaintext,
                Some(hex::encode(b"my_auth_data").into_bytes()),
            )?;

            let cleartext = DecryptAction::default()
                .client_side_decrypt_with_buffer(
                    &kms_rest_client,
                    dea,
                    &kek,
                    &ciphertext,
                    Some(hex::encode(b"my_auth_data").into_bytes()),
                )
                .await?;

            assert_eq!(cleartext, plaintext);
        }
    }

    Ok(())
}

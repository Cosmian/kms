use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_bytes_from_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;

use super::SUB_COMMAND;
use crate::{
    actions::symmetric::{DataEncryptionAlgorithm, KeyEncryptionAlgorithm},
    error::{result::CliResult, CliError},
    tests::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs, PROG_NAME},
};

const fn dek_algorithm_to_string(alg: DataEncryptionAlgorithm) -> &'static str {
    match alg {
        #[cfg(not(feature = "fips"))]
        DataEncryptionAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
        DataEncryptionAlgorithm::AesGcm => "aes-gcm",
        DataEncryptionAlgorithm::AesXts => "aes-xts",
        #[cfg(not(feature = "fips"))]
        DataEncryptionAlgorithm::AesGcmSiv => "aes-gcm-siv",
    }
}

const fn kek_algorithm_to_string(alg: KeyEncryptionAlgorithm) -> &'static str {
    match alg {
        #[cfg(not(feature = "fips"))]
        KeyEncryptionAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
        KeyEncryptionAlgorithm::AesGcm => "aes-gcm",
        KeyEncryptionAlgorithm::AesXts => "aes-xts",
        #[cfg(not(feature = "fips"))]
        KeyEncryptionAlgorithm::AesGcmSiv => "aes-gcm-siv",
        KeyEncryptionAlgorithm::RFC5649 => "rfc5649",
    }
}

/// Encrypts a file using the given symmetric key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    symmetric_key_id: &str,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "encrypt",
        input_file,
        "--key-id",
        symmetric_key_id,
        "-d",
        dek_algorithm_to_string(data_encryption_algorithm),
    ];
    if let Some(key_encryption_algorithm) = key_encryption_algorithm {
        args.push("-e");
        args.push(kek_algorithm_to_string(key_encryption_algorithm));
    }
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
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
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "decrypt",
        input_file,
        "--key-id",
        symmetric_key_id,
        "-d",
        dek_algorithm_to_string(data_encryption_algorithm),
    ];
    if let Some(key_encryption_algorithm) = key_encryption_algorithm {
        args.push("-e");
        args.push(kek_algorithm_to_string(key_encryption_algorithm));
    }
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn run_encrypt_decrypt_test(
    cli_conf_path: &str,
    key_id: &str,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    encryption_overhead: u64,
) -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )))
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
        return Err(CliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )))
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )))
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_server_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        None,
        12 /* nonce */  + 16, /* tag */
    )
}

#[tokio::test]
async fn test_aes_xts_server_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(512),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesXts,
        None,
        16, /* tweak */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_aes_gcm_siv_server_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcmSiv,
        None,
        12 /* nonce */ + 16, /* ag */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_chacha20_poly1305_server_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("chacha20"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        12 /* nonce */ + 16, /* ag */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_encrypt_decrypt_with_tags() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;
    let _key_id =
        create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &["tag_sym"])?;

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(CliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )))
    }

    encrypt(
        &ctx.owner_client_conf_path,
        input_file.to_str().unwrap(),
        "[\"tag_sym\"]",
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        Some(output_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        "[\"tag_sym\"]",
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        Some(recovered_file.to_str().unwrap()),
        Some(&hex::encode(b"myid")),
    )?;
    if !recovered_file.exists() {
        return Err(CliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )))
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(CliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )))
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_aes_gcm_client_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[tokio::test]
async fn test_aes_gcm_aes_xts_client_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesXts,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 64 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 16, /* tweak */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_aes_gcm_chacha20_client_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[tokio::test]
async fn test_rfc5649_aes_gcm_client_side() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        Some(256),
        None,
        Some("aes"),
        &[],
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::RFC5649),
        8 + 32 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */ + 16, /* tag */
    )
}

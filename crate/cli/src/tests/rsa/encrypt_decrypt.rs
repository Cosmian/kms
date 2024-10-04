use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_bytes_from_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use predicates::prelude::*;
use tempfile::TempDir;
use tracing::trace;

use super::SUB_COMMAND;
use crate::{
    actions::rsa::{EncryptionAlgorithm, HashFn},
    error::{result::CliResult, CliError},
    tests::{
        rsa::create_key_pair::create_rsa_4096_bits_key_pair, utils::recover_cmd_logs, PROG_NAME,
    },
};

/// Encrypts a file using the given public key
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    public_key_id: &str,
    encryption_algorithm: EncryptionAlgorithm,
    hash_fn: Option<HashFn>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt"];
    args.append(&mut input_files.to_vec());
    args.push("--key-id");
    args.push(public_key_id);
    args.push("--encryption-algorithm");
    let encryption_algorithm = encryption_algorithm.to_string();
    args.push(&encryption_algorithm);
    let hash_fn_s = hash_fn.map(|h| h.to_string()).unwrap_or_default();
    if hash_fn.is_some() {
        args.push("--hashing-algorithm");
        args.push(&hash_fn_s);
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
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "The encrypted file is available at",
    ));
    Ok(())
}

/// Decrypt a file using the given private key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    encryption_algorithm: EncryptionAlgorithm,
    hash_fn: Option<HashFn>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", input_file, "--key-id", private_key_id];
    args.push("--encryption-algorithm");
    let encryption_algorithm = encryption_algorithm.to_string();
    args.push(&encryption_algorithm);
    let hash_fn_str = hash_fn.map(|h| h.to_string()).unwrap_or_default();
    if hash_fn.is_some() {
        args.push("--hashing-algorithm");
        args.push(&hash_fn_str);
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

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs() -> CliResult<()> {
    // to enable this, add cosmian_logger = { path = "../logger" } to dev-dependencies in Cargo.toml
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=info,cosmian_kms_server::core::operations=trace,\
    //      cosmian_kms_utils=trace,cosmian_kmip=info",
    // );

    use tracing::trace;
    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        EncryptionAlgorithm::CkmRsaPkcs,
        None,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        EncryptionAlgorithm::CkmRsaPkcs,
        None,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaAesKeyWrap,
            None,
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs_oaep() -> CliResult<()> {
    // to enable this, add cosmian_logger = { path = "../logger" } to dev-dependencies in Cargo.toml
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=info,cosmian_kms_server::core::operations=trace,\
    //      cosmian_kms_utils=trace,cosmian_kmip=info",
    // );
    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaAesKeyWrap,
            Some(HashFn::Sha256),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaPkcsOaep,
            Some(HashFn::Sha1),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_rsa_aes_key_wrap() -> CliResult<()> {
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=trace,cosmian_kms_utils=trace,cosmian_kmip=trace",
    // );
    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        EncryptionAlgorithm::CkmRsaAesKeyWrap,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        EncryptionAlgorithm::CkmRsaAesKeyWrap,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaPkcsOaep,
            Some(HashFn::Sha256),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaAesKeyWrap,
            Some(HashFn::Sha1),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_tags() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (_private_key_id, _public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &["tag_rsa"])?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        "[\"tag_rsa\"]",
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        "[\"tag_rsa\"]",
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

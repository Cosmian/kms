use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

use super::SUB_COMMAND;
use crate::{
    actions::{
        rsa::{EncryptionAlgorithm, HashFn},
        shared::utils::read_bytes_from_file,
    },
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        rsa::create_key_pair::create_rsa_4096_bits_key_pair,
        utils::{recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

/// Encrypts a file using the given public key
pub fn encrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    public_key_id: &str,
    encryption_algorithm: EncryptionAlgorithm,
    hash_fn: HashFn,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");

    let mut args = vec!["encrypt"];
    args.append(&mut input_files.to_vec());
    args.push("--key-id");
    args.push(public_key_id);
    args.push("--encryption-algorithm");
    args.push(match encryption_algorithm {
        EncryptionAlgorithm::CkmRsaPkcsOaep => "ckm-rsa-pkcs-oaep",
        EncryptionAlgorithm::RsaOaepAes128Gcm => "rsa-oaep-aes128-gcm",
    });
    args.push("--hashing-algorithm");
    args.push(match hash_fn {
        HashFn::Sha1 => "sha1",
        HashFn::Sha224 => "sha224",
        HashFn::Sha256 => "sha256",
        HashFn::Sha384 => "sha384",
        HashFn::Sha512 => "sha512",
        HashFn::Sha3_224 => "sha3-224",
        HashFn::Sha3_256 => "sha3-256",
        HashFn::Sha3_384 => "sha3-384",
        HashFn::Sha3_512 => "sha3-512",
    });
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
pub fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    encryption_algorithm: EncryptionAlgorithm,
    hash_fn: HashFn,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    let mut args = vec!["decrypt", input_file, "--key-id", private_key_id];
    args.push("--encryption-algorithm");
    args.push(match encryption_algorithm {
        EncryptionAlgorithm::CkmRsaPkcsOaep => "ckm-rsa-pkcs-oaep",
        EncryptionAlgorithm::RsaOaepAes128Gcm => "rsa-oaep-aes128-gcm",
    });
    args.push("--hashing-algorithm");
    args.push(match hash_fn {
        HashFn::Sha1 => "sha1",
        HashFn::Sha224 => "sha224",
        HashFn::Sha256 => "sha256",
        HashFn::Sha384 => "sha384",
        HashFn::Sha512 => "sha512",
        HashFn::Sha3_224 => "sha3-224",
        HashFn::Sha3_256 => "sha3-256",
        HashFn::Sha3_384 => "sha3-384",
        HashFn::Sha3_512 => "sha3-512",
    });
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

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs_oaep() -> Result<(), CliError> {
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=trace,cosmian_kms_utils=trace,cosmian_kmip=trace",
    // );
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_cli_conf_path, &[])?;

    println!("private_key_id: {private_key_id}");
    println!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_cli_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        HashFn::Sha256,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        HashFn::Sha256,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_cli_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::RsaOaepAes128Gcm,
            HashFn::Sha256,
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &ctx.owner_cli_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaPkcsOaep,
            HashFn::Sha1,
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
async fn test_rsa_encrypt_decrypt_using_rsa_oaep_aes128gcm() -> Result<(), CliError> {
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=trace,cosmian_kms_utils=trace,cosmian_kmip=trace",
    // );
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_cli_conf_path, &[])?;

    println!("private_key_id: {private_key_id}");
    println!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_cli_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        EncryptionAlgorithm::RsaOaepAes128Gcm,
        HashFn::Sha256,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        EncryptionAlgorithm::RsaOaepAes128Gcm,
        HashFn::Sha256,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_cli_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::CkmRsaPkcsOaep,
            HashFn::Sha256,
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &ctx.owner_cli_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            EncryptionAlgorithm::RsaOaepAes128Gcm,
            HashFn::Sha1,
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
async fn test_rsa_encrypt_decrypt_using_tags() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (_private_key_id, _public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_cli_conf_path, &["tag_rsa"])?;

    encrypt(
        &ctx.owner_cli_conf_path,
        &[input_file.to_str().unwrap()],
        "[\"tag_rsa\"]",
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        HashFn::Sha256,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        "[\"tag_rsa\"]",
        EncryptionAlgorithm::CkmRsaPkcsOaep,
        HashFn::Sha256,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

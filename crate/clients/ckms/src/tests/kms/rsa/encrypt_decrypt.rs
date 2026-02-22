use std::{collections::HashSet, fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use clap::ValueEnum;
use cosmian_kms_cli::reexport::cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};
use cosmian_logger::trace;
use predicates::prelude::*;
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
            rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

/// Encrypts a file using the given public key
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    public_key_id: &str,
    encryption_algorithm: RsaEncryptionAlgorithm,
    hash_fn: Option<HashFn>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt"];
    args.append(&mut input_files.to_vec());
    args.push("--key-id");
    args.push(public_key_id);
    args.push("--encryption-algorithm");
    let encryption_algorithm = encryption_algorithm
        .to_possible_value()
        .expect("valid RSA algorithm")
        .get_name()
        .to_string();
    args.push(&encryption_algorithm);
    let hash_fn_s = hash_fn
        .map(|h| {
            h.to_possible_value()
                .expect("valid hash")
                .get_name()
                .to_string()
        })
        .unwrap_or_default();
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
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
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
    encryption_algorithm: RsaEncryptionAlgorithm,
    hash_fn: Option<HashFn>,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", input_file, "--key-id", private_key_id];
    args.push("--encryption-algorithm");
    let encryption_algorithm = encryption_algorithm
        .to_possible_value()
        .expect("valid RSA algorithm")
        .get_name()
        .to_string();
    args.push(&encryption_algorithm);
    let hash_fn_str = hash_fn
        .map(|h| {
            h.to_possible_value()
                .expect("valid hash")
                .get_name()
                .to_string()
        })
        .unwrap_or_default();
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
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs() -> CosmianResult<()> {
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=info,cosmian_kms_server::core::operations=trace,\
    //      cosmian_kms_utils=trace,cosmian_kmip=info",
    // );

    use cosmian_logger::trace;
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_key_pair(&owner_client_conf_path, &RsaKeyPairOptions::default())?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcs,
        None,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcs,
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
            &owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
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
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs_oaep() -> CosmianResult<()> {
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=info,cosmian_kms_server::core::operations=trace,\
    //      cosmian_kms_utils=trace,cosmian_kmip=info",
    // );
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_key_pair(&owner_client_conf_path, &RsaKeyPairOptions::default())?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
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
            &owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
            Some(HashFn::Sha256),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
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
async fn test_rsa_encrypt_decrypt_using_rsa_aes_key_wrap() -> CosmianResult<()> {
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=trace,cosmian_kms_utils=trace,cosmian_kmip=trace",
    // );
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) =
        create_rsa_key_pair(&owner_client_conf_path, &RsaKeyPairOptions::default())?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
            Some(HashFn::Sha256),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    // ... or another hash function
    assert!(
        decrypt(
            &owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
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
async fn test_rsa_encrypt_decrypt_using_tags() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            tags: HashSet::from(["tag_rsa".to_string()]),
            ..Default::default()
        },
    )?;

    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
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

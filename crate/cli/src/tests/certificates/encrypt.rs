use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_logger::log_utils::log_init;
use tempfile::TempDir;
use tracing::debug;
use uuid::Uuid;

use super::SUB_COMMAND;
use crate::{
    actions::{
        certificates::CertificateInputFormat,
        shared::{import_key::ImportKeyFormat, utils::read_bytes_from_file, ExportKeyFormat},
    },
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        certificates::import::import_certificate,
        shared::{export_key, import_key},
        utils::{recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

/// Encrypts a file using the given public key and access policy.
pub fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    certificate_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug");
    let mut args = vec!["encrypt", "--certificate-id", certificate_id, input_file];
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

/// Decrypt a file using the given private key
pub fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug");
    let mut args = vec!["decrypt", "--key-id", private_key_id, input_file];
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

// #[tokio::test]
// async fn test_certificate_encrypt_decrypt_certify() -> Result<(), CliError> {
//     let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
//     // create a temp dir
//     let tmp_dir = TempDir::new()?;
//     let tmp_path = tmp_dir.path();
//
//     let input_file = PathBuf::from("test_data/plain.txt");
//     let output_file = tmp_path.join("plain.enc");
//     let recovered_file = tmp_path.join("plain.txt");
//
//     let tags = &["certificate_encryption"];
//
//     fs::remove_file(&output_file).ok();
//     assert!(!output_file.exists());
//
//     let certificate_id = certify(
//         &ctx.owner_cli_conf_path,
//         "CA",
//         Some("My server".to_string()),
//         None,
//         None,
//         tags,
//     )?;
//
//     encrypt(
//         &ctx.owner_cli_conf_path,
//         input_file.to_str().unwrap(),
//         &certificate_id,
//         Some(output_file.to_str().unwrap()),
//         None,
//     )?;
//
//     // locate the private key matching the certificate id
//     let priv_key_tags = &[
//         "certificate_encryption",
//         &format!("_cert_uid={certificate_id}"),
//     ];
//     let ids = locate(
//         &ctx.owner_cli_conf_path,
//         Some(priv_key_tags),
//         Some("ECDH"),
//         None,
//         Some("TransparentECPrivateKey"),
//     )?;
//     assert_eq!(ids.len(), 1);
//     let private_key_id = ids[0].clone();
//
//     // the user key should be able to decrypt the file
//     decrypt(
//         &ctx.owner_cli_conf_path,
//         output_file.to_str().unwrap(),
//         &private_key_id,
//         Some(recovered_file.to_str().unwrap()),
//         None,
//     )?;
//     assert!(recovered_file.exists());
//
//     let original_content = read_bytes_from_file(&input_file)?;
//     let recovered_content = read_bytes_from_file(&recovered_file)?;
//     assert_eq!(original_content, recovered_content);
//
//     Ok(())
// }

async fn test_certificate_import_encrypt(
    ca_path: &str,
    subca_path: &str,
    cert_path: &str,
    key_path: &str,
    tags: &[&str],
) -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    debug!("\n\nImport Key");
    let private_key_id = import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &format!("test_data/certificates/{key_path}"),
        Some(ImportKeyFormat::Pem),
        None,
        tags.iter()
            .map(|&s| s.to_string())
            .collect::<Vec<String>>()
            .as_slice(),
        false,
        true,
    )?;

    let root_certificate_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{ca_path}"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        None,
        Some(tags),
        false,
        true,
    )?;

    let _subca_certificate_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{subca_path}"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(root_certificate_id),
        Some(tags),
        false,
        true,
    )?;

    let certificate_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{cert_path}"),
        CertificateInputFormat::Pem,
        None,
        None,
        Some(private_key_id.clone()),
        Some(_subca_certificate_id),
        Some(tags),
        false,
        true,
    )?;

    debug!("\n\nEncrypt With Certificate");
    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    debug!("\n\nDecrypt");
    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_certificate_import_ca_and_encrypt_using_x25519() -> Result<(), CliError> {
    test_certificate_import_encrypt(
        "p12/root.pem",
        "p12/subca.pem",
        "p12/cert.pem",
        "p12/cert.key",
        &["external_certificate"],
    )
    .await
}

async fn import_encrypt_decrypt(curve_name: &str) -> Result<(), CliError> {
    log_init("cosmian_kms_cli=debug,cosmian_kms_server=debug");
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    let tags = &[curve_name];

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    debug!("\n\nImport Private key");
    let private_key_id = import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &format!("test_data/certificates/openssl/{curve_name}-private-key.pem"),
        Some(ImportKeyFormat::Pem),
        Some(Uuid::new_v4().to_string()),
        tags.iter()
            .map(|&s| s.to_string())
            .collect::<Vec<String>>()
            .as_slice(),
        false,
        true,
    )?;

    debug!("\n\nImport Certificate");
    let certificate_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-cert.pem"),
        CertificateInputFormat::Pem,
        None,
        Some(Uuid::new_v4().to_string()),
        Some(private_key_id.clone()),
        None,
        Some(tags),
        false,
        true,
    )?;

    debug!("\n\nEncrypt with certificate");
    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    debug!("\n\nExport Private key wrapping with X509 certificate");
    let private_key_wrapped = tmp_path
        .join("wrapped_private_key_exported.json")
        .to_str()
        .unwrap()
        .to_owned();
    export_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        &private_key_wrapped,
        Some(ExportKeyFormat::JsonTtlv),
        false,
        Some(certificate_id),
        false,
    )?;

    debug!("\n\nImport a wrapped Private key but unwrap it into server");
    import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_wrapped,
        Some(ImportKeyFormat::JsonTtlv),
        Some(Uuid::new_v4().to_string()),
        &[],
        true,
        true,
    )?;

    debug!("\n\nImport a wrapped Private key but let is save it `as registered` into server");
    let wrapped_private_key_uid = import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_wrapped,
        Some(ImportKeyFormat::JsonTtlv),
        Some(Uuid::new_v4().to_string()),
        &[],
        false,
        true,
    )?;

    debug!("\n\nExport the wrapped Private key without unwrapping");
    let private_key_wrapped_as_is = tmp_path
        .join("wrapped_private_key.json")
        .to_str()
        .unwrap()
        .to_owned();
    export_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &wrapped_private_key_uid,
        &private_key_wrapped_as_is,
        Some(ExportKeyFormat::JsonTtlv),
        false,
        None,
        false,
    )?;

    debug!("\n\nDecrypt using Private key");
    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_cli_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);
    Ok(())
}

#[tokio::test]
async fn test_certificate_encrypt_using_prime192() -> Result<(), CliError> {
    import_encrypt_decrypt("prime192v1").await
}

#[tokio::test]
async fn test_certificate_encrypt_using_prime224() -> Result<(), CliError> {
    import_encrypt_decrypt("secp224r1").await
}

#[tokio::test]
async fn test_certificate_encrypt_using_ed25519() -> Result<(), CliError> {
    import_encrypt_decrypt("ED25519").await
}

#[tokio::test]
async fn test_certificate_encrypt_using_prime256() -> Result<(), CliError> {
    import_encrypt_decrypt("prime256v1").await
}

#[tokio::test]
async fn test_certificate_encrypt_using_secp384r1() -> Result<(), CliError> {
    import_encrypt_decrypt("secp384r1").await
}

#[tokio::test]
async fn test_certificate_encrypt_using_rsa() -> Result<(), CliError> {
    import_encrypt_decrypt("rsa-2048").await?;
    import_encrypt_decrypt("rsa-3072").await?;
    import_encrypt_decrypt("rsa-4096").await
}

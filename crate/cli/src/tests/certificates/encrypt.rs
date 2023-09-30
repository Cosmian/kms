use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use tracing::debug;

use super::SUB_COMMAND;
use crate::{
    actions::{
        certificates::{CertificateExportFormat, CertificateInputFormat},
        shared::utils::read_bytes_from_file,
    },
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        certificates::{
            certify::{certify, export},
            import::import,
        },
        shared::locate,
        utils::{start_default_test_kms_server, ONCE},
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
    let output = cmd.output()?;
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
    let output = cmd.output()?;
    println!("output: {output:?}");
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_certificate_encrypt_decrypt() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    let tags = &["certificate_encryption"];

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let certificate_id = certify(&ctx.owner_cli_conf_path, "CA", "My server", tags)?;

    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // locate the private key matching the certificate id
    let priv_key_tags = &[
        "certificate_encryption",
        &format!("_cert_uid={certificate_id}"),
    ];
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(priv_key_tags),
        Some("ECDH"),
        None,
        Some("TransparentECPrivateKey"),
    )?;
    assert_eq!(ids.len(), 1);
    let private_key_id = ids[0].clone();

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

    let _root_certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{ca_path}"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    let _subca_certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{subca_path}"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    let certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{cert_path}"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    debug!("\n\nEncrypt Certificate");
    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    debug!("\n\nImport Key");
    let private_key_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/{key_path}"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
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
        "kms/root.pem",
        "kms/subca.pem",
        "kms/cert.pem",
        "kms/cert.key",
        &["external_certificate"],
    )
    .await
}

async fn import_encrypt_decrypt(curve_name: &str) -> Result<(), CliError> {
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

    debug!("\n\nImport Certificate");
    let certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-cert.pem"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    debug!("\n\nEncrypt with certificate");
    encrypt(
        &ctx.owner_cli_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    debug!("\n\nImport Private key");
    let private_key_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-private-key.pem"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    debug!("\n\nExport Private key wrapping with X509 certificate");
    let private_key_wrapped = tmp_path
        .join("wrapped_private_key_exported.json")
        .to_str()
        .unwrap()
        .to_owned();
    export(
        &ctx.owner_cli_conf_path,
        "certificates",
        None,
        &private_key_id,
        &private_key_wrapped,
        CertificateExportFormat::TTLV,
        Some(certificate_id),
        false,
    )?;

    debug!("\n\nImport a wrapped Private key but unwrap it into server");
    import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &private_key_wrapped,
        CertificateInputFormat::TTLV,
        None,
        None,
        true,
        true,
    )?;

    debug!("\n\nImport a wrapped Private key but let is save it `as registered` into server");
    let wrapped_private_key_uid = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &private_key_wrapped,
        CertificateInputFormat::TTLV,
        None,
        None,
        false,
        false,
    )?;

    debug!("\n\nExport the wrapped Private key without unwrapping");
    let private_key_wrapped_as_is = tmp_path
        .join("wrapped_private_key.json")
        .to_str()
        .unwrap()
        .to_owned();
    export(
        &ctx.owner_cli_conf_path,
        "certificates",
        None,
        &wrapped_private_key_uid,
        &private_key_wrapped_as_is,
        CertificateExportFormat::TTLV,
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

// The 2 following tests have been commented out because no support of signature verification is available in the crate `x509-parser`.

// #[tokio::test]
// async fn test_certificate_encrypt_using_prime192() -> Result<(), CliError> {
//     import_encrypt_decrypt("prime192v1").await
// }

// #[tokio::test]
// async fn test_certificate_encrypt_using_prime224() -> Result<(), CliError> {
//     import_encrypt_decrypt("secp224r1").await
// }

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
    import_encrypt_decrypt("rsa").await
}

async fn import_revoked_certificate_encrypt(curve_name: &str) -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let _recovered_file = tmp_path.join("plain.txt");

    let tags = &[curve_name];

    fs::remove_file(&output_file).ok();
    // assert!(!output_file.exists());

    debug!("\n\nImport Certificate");
    let _root_certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-cert.pem"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    debug!("\n\nImport Certificate");
    let certificate_id = import(
        &ctx.owner_cli_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-revoked.crt"),
        CertificateInputFormat::PEM,
        None,
        Some(tags),
        false,
        false,
    )?;

    debug!("\n\nEncrypt with certificate");
    assert!(
        encrypt(
            &ctx.owner_cli_conf_path,
            input_file.to_str().unwrap(),
            &certificate_id,
            Some(output_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_import_revoked_certificate_encrypt_prime256() -> Result<(), CliError> {
    import_revoked_certificate_encrypt("prime256v1").await
}

use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_cli::reexport::cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::{ExportKeyFormat, WrappingAlgorithm},
        import_utils::{CertificateInputFormat, ImportKeyFormat, KeyUsage},
        rsa_utils::RsaEncryptionAlgorithm,
    },
};
use cosmian_logger::{debug, trace};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
use uuid::Uuid;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            certificates::import::{ImportCertificateInput, import_certificate},
            shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

/// Encrypts a file using the given public key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_file: &str,
    certificate_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt", "--certificate-id", certificate_id, input_file];
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    if let Some(encryption_algorithm) = encryption_algorithm {
        args.push("-e");
        args.push(encryption_algorithm.as_str());
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

/// Decrypt a file using the given private key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_file: &str,
    private_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", "--key-id", private_key_id, input_file];
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    if let Some(encryption_algorithm) = encryption_algorithm {
        args.push("-e");
        args.push(encryption_algorithm.as_str());
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

#[cfg(feature = "non-fips")]
#[allow(clippy::cognitive_complexity)]
async fn test_certificate_import_encrypt(
    ca_path: &str,
    subca_path: &str,
    cert_path: &str,
    key_path: &str,
    tags: &[&str],
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> CosmianResult<()> {
    use crate::tests::{kms::shared::ImportKeyParams, save_kms_cli_config};

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

    debug!("\n\nImport Key");
    let private_key_id = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: format!("../../../test_data/certificates/{key_path}"),
        key_format: Some(ImportKeyFormat::Pem),
        tags: tags.iter().map(|&s| s.to_string()).collect::<Vec<String>>(),
        replace_existing: true,
        ..Default::default()
    })?;

    let root_certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: &format!("../../../test_data/certificates/{ca_path}"),
        format: &CertificateInputFormat::Pem,
        tags: Some(tags),
        ..Default::default()
    })?;

    let subca_certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: &format!("../../../test_data/certificates/{subca_path}"),
        format: &CertificateInputFormat::Pem,
        issuer_certificate_id: Some(root_certificate_id),
        tags: Some(tags),
        ..Default::default()
    })?;

    let certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: &format!("../../../test_data/certificates/{cert_path}"),
        format: &CertificateInputFormat::Pem,
        private_key_id: Some(private_key_id.clone()),
        issuer_certificate_id: Some(subca_certificate_id),
        tags: Some(tags),
        unwrap: false,
        replace_existing: true,
        ..Default::default()
    })?;

    debug!("\n\nEncrypt With Certificate");
    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
        encryption_algorithm,
    )?;

    debug!("\n\nDecrypt");
    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        Some(recovered_file.to_str().unwrap()),
        None,
        encryption_algorithm,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_import_ca_and_encrypt_using_x25519() -> CosmianResult<()> {
    test_certificate_import_encrypt(
        "p12/root.pem",
        "p12/subca.pem",
        "p12/cert.pem",
        "p12/cert.key",
        &["external_certificate"],
        None,
    )
    .await
}

#[allow(clippy::cognitive_complexity)]
async fn import_encrypt_decrypt(
    filename: &str,
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file = tmp_path.join(format!("{filename}-plain.enc"));
    let recovered_file = tmp_path.join(format!("{filename}-plain.txt"));

    let tags = &[filename];

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    debug!("\n\nImport Private key");
    let private_key_id = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: format!("../../../test_data/certificates/openssl/{filename}-private-key.pem"),
        key_format: Some(ImportKeyFormat::Pem),
        key_id: Some(Uuid::new_v4().to_string()),
        tags: tags.iter().map(|&s| s.to_string()).collect::<Vec<String>>(),
        key_usage_vec: Some(vec![KeyUsage::Decrypt, KeyUsage::UnwrapKey]),
        replace_existing: true,
        ..Default::default()
    })?;

    debug!("\n\nImport Certificate");
    let certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: &format!("../../../test_data/certificates/openssl/{filename}-cert.pem"),
        format: &CertificateInputFormat::Pem,
        pkcs12_password: None,
        certificate_id: Some(Uuid::new_v4().to_string()),
        private_key_id: Some(private_key_id.clone()),
        public_key_id: None,
        issuer_certificate_id: None,
        tags: Some(tags),
        key_usage_vec: Some(vec![KeyUsage::Encrypt]),
        unwrap: false,
        replace_existing: true,
    })?;

    debug!("\n\nEncrypt with certificate");
    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        &certificate_id,
        Some(output_file.to_str().unwrap()),
        None,
        encryption_algorithm,
    )?;

    debug!("\n\nExport Private key wrapping with X509 certificate");
    // Use a cross-platform temporary path instead of hard-coding /tmp
    let private_key_wrapped = tmp_path
        .join(format!("wrapped_{filename}_private_key_exported.json"))
        .to_string_lossy()
        .to_string();

    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: private_key_id.clone(),
        key_file: private_key_wrapped.clone(),
        key_format: Some(ExportKeyFormat::JsonTtlv),
        wrap_key_id: Some(certificate_id),
        wrapping_algorithm: Some(WrappingAlgorithm::RsaAesKeyWrap),
        ..Default::default()
    })?;

    trace!("import private key with unwrap");
    debug!("\n\nImport a wrapped Private key but unwrap it into server");
    import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: private_key_wrapped.clone(),
        key_format: Some(ImportKeyFormat::JsonTtlv),
        key_id: Some(Uuid::new_v4().to_string()),
        public_key_id: None,
        private_key_id: None,
        certificate_id: None,
        tags: vec![],
        key_usage_vec: Some(vec![KeyUsage::Decrypt]),
        unwrap: true,
        replace_existing: true,
        authenticated_additional_data: None,
    })?;
    trace!("import private key with unwrap OK");
    debug!("\n\nImport a wrapped Private key but let is save it `as registered` into server");
    let wrapped_private_key_uid = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: private_key_wrapped,
        key_format: Some(ImportKeyFormat::JsonTtlv),
        key_id: Some(Uuid::new_v4().to_string()),
        key_usage_vec: Some(vec![KeyUsage::Decrypt]),
        replace_existing: true,
        ..Default::default()
    })?;

    debug!("\n\nExport the wrapped Private key without unwrapping");
    let private_key_wrapped_as_is = tmp_path
        .join(format!("wrapped_{filename}_private_key.json"))
        .to_str()
        .unwrap()
        .to_owned();
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: wrapped_private_key_uid,
        key_file: private_key_wrapped_as_is,
        key_format: Some(ExportKeyFormat::JsonTtlv),
        ..Default::default()
    })?;

    debug!("\n\nDecrypt using Private key");
    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        Some(recovered_file.to_str().unwrap()),
        None,
        encryption_algorithm,
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);
    Ok(())
}

#[tokio::test]
#[cfg(feature = "non-fips")]
// P-192 should not be used in FIPS mode. See NIST.SP.800-186 - Section 3.2.1.1.
async fn test_certificate_encrypt_using_prime192() -> CosmianResult<()> {
    import_encrypt_decrypt("prime192v1", None).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_prime224() -> CosmianResult<()> {
    import_encrypt_decrypt("secp224r1", None).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
// Edwards curve shall be used **for digital signature only**.
// See NIST.SP.800-186 - Section 3.1.2 table 2 and NIST.FIPS.186-5.
async fn test_certificate_encrypt_using_ed25519() -> CosmianResult<()> {
    import_encrypt_decrypt("ED25519", None).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_prime256() -> CosmianResult<()> {
    import_encrypt_decrypt("prime256v1", None).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_secp384r1() -> CosmianResult<()> {
    import_encrypt_decrypt("secp384r1", None).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_secp521r1() -> CosmianResult<()> {
    import_encrypt_decrypt("secp521r1", None).await
}

#[tokio::test]
async fn test_certificate_encrypt_using_rsa() -> CosmianResult<()> {
    import_encrypt_decrypt("rsa-2048", Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap)).await?;
    import_encrypt_decrypt("rsa-3072", Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap)).await?;
    import_encrypt_decrypt("rsa-4096", Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap)).await
}

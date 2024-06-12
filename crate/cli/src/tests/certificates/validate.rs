use std::{
    fs,
    path::{self, PathBuf},
    process::Command,
};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::{start_default_test_kms_server, ONCE};
use openssl::x509::X509;
use tempfile::TempDir;
use tracing::debug;

use crate::{
    actions::certificates::CertificateInputFormat,
    error::CliError,
    tests::{
        certificates::{encrypt::encrypt, import::import_certificate},
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

async fn import_revoked_certificate_encrypt(curve_name: &str) -> Result<(), CliError> {
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let _recovered_file = tmp_path.join("plain.txt");

    let tags = &[curve_name];

    std::fs::remove_file(&output_file).ok();
    // assert!(!output_file.exists());

    debug!("\n\nImport Certificate");
    let root_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-cert.pem"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        None,
        Some(tags),
        None,
        false,
        true,
    )?;

    debug!("\n\nImport Certificate");
    let certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-revoked.crt"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(root_certificate_id),
        Some(tags),
        None,
        false,
        true,
    )?;

    debug!("\n\nEncrypt with certificate");
    assert!(
        encrypt(
            &ctx.owner_client_conf_path,
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
#[ignore]
async fn test_import_revoked_certificate_encrypt_prime256() -> Result<(), CliError> {
    import_revoked_certificate_encrypt("prime256v1").await
}

async fn validate_certificate(
    cli_conf_path: &str,
    sub_command: &str,
    certificates: Vec<String>,
    uids: Vec<String>,
    date: String,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    let mut args: Vec<String> = vec!["validate".to_owned()];
    for certificate in certificates {
        args.push("--certificate".to_owned());
        args.push(certificate);
    }
    for uid in uids {
        args.push("--unique-identifier".to_owned());
        args.push(uid);
    }
    args.push("--validity-time".to_owned());
    args.push(date.to_owned());
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_validate() -> Result<(), CliError> {
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    println!("importing root cert");
    let root_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/chain/ca.cert.pem",
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        true,
    )?;

    println!("importing intermediate cert");
    let intermediate_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/chain/intermediate.cert.pem",
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(root_certificate_id.clone()),
        None,
        None,
        false,
        true,
    )?;

    println!("importing leaf1 cert");

    let leaf1_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/chain/leaf1.cert.pem",
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(intermediate_certificate_id.clone()),
        None,
        None,
        false,
        true,
    )?;

    println!("importing leaf2 cert");

    let leaf2_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/chain/leaf2.cert.pem",
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(intermediate_certificate_id.clone()),
        None,
        None,
        false,
        true,
    )?;

    println!("validating chain with leaf1: Result supposed to be invalid, as leaf1 was removed");

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [].to_vec(),
        [
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf1_certificate_id.clone(),
        ]
        .to_vec(),
        "".to_string(),
    )
    .await?;

    println!(
        "validating chain with leaf2: Result supposed to be valid, as leaf2 was never removed"
    );

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [].to_vec(),
        [
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf2_certificate_id.clone(),
        ]
        .to_vec(),
        "".to_string(),
    )
    .await?;

    println!(
        "validating chain with leaf2: Result supposed to be invalid, as date is postumous to \
         leaf2's expiration date"
    );

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [].to_vec(),
        [
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf2_certificate_id.clone(),
        ]
        .to_vec(),
        // Date: 15/04/2048
        "4804152030Z".to_string(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_validate_1() -> Result<(), CliError> {
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    let root_path = path::Path::new("test_data/certificates/chain/ca.cert.der");
    let intermediate_path = path::Path::new("test_data/certificates/chain/intermediate.cert.der");
    let leaf1_path = path::Path::new("test_data/certificates/chain/leaf1.cert.der"); // invalid
    let leaf2_path = path::Path::new("test_data/certificates/chain/leaf2.cert.der"); // valid

    let root_cert = fs::read(root_path)?;
    let root_cert = String::from_utf8(X509::from_der(&root_cert).unwrap().to_text().unwrap())?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let intermediate_cert = String::from_utf8(
        X509::from_der(&intermediate_cert)
            .unwrap()
            .to_text()
            .unwrap(),
    )?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf1_cert = String::from_utf8(X509::from_der(&leaf1_cert).unwrap().to_text().unwrap())?;
    let leaf2_cert = fs::read(leaf2_path)?;
    let leaf2_cert = String::from_utf8(X509::from_der(&leaf2_cert).unwrap().to_text().unwrap())?;

    println!("validating chain with leaf1: Result supposed to be invalid, as leaf1 was removed");

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [
            intermediate_cert.clone(),
            root_cert.clone(),
            leaf1_cert.clone(),
        ]
        .to_vec(),
        [].to_vec(),
        "".to_string(),
    )
    .await?;

    println!(
        "validating chain with leaf2: Result supposed to be valid, as leaf2 was never removed"
    );

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [
            intermediate_cert.clone(),
            root_cert.clone(),
            leaf2_cert.clone(),
        ]
        .to_vec(),
        [].to_vec(),
        "".to_string(),
    )
    .await?;

    println!(
        "validating chain with leaf2: Result supposed to be invalid, as date is postumous to \
         leaf2's expiration date"
    );

    validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        [
            intermediate_cert.clone(),
            root_cert.clone(),
            leaf2_cert.clone(),
        ]
        .to_vec(),
        [].to_vec(),
        // Date: 15/04/2048
        "4804152030Z".to_string(),
    )
    .await?;

    Ok(())
}

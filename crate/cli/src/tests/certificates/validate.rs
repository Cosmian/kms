use std::{path::PathBuf, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::{start_default_test_kms_server, ONCE};
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
    certificates: Vec<String>,
    uids: Vec<String>,
    date: String,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    let mut args: Vec<Vec<String>> = vec![["validate".to_owned()].to_vec()];
    args.push(["--certificate".to_owned()].to_vec());
    args.push(certificates);
    args.push(["--unique-identifier".to_owned()].to_vec());
    args.push(uids);
    args.push(["--validity-time".to_owned()].to_vec());
    args.push([date].to_vec());

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
#[ignore]
async fn test_validate() -> Result<(), CliError> {
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    println!("importing root cert");
    let root_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "../server/src/tests/certificates/chain/root/ca/ca.cert.pem",
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
        "../server/src/tests/certificates/chain/root/ca/intermediate.cert.pem",
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
        "../server/src/tests/certificates/chain/root/ca/leaf1.cert.pem",
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
        "../server/src/tests/certificates/chain/root/ca/leaf2.cert.pem",
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

    println!("validating chain with leaf1: Result supposed to be invalid");

    validate_certificate(
        &ctx.owner_client_conf_path,
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

    println!("validating chain with leaf2: Result supposed to be valid");

    validate_certificate(
        &ctx.owner_client_conf_path,
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

    Ok(())
}

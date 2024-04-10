use std::{path::PathBuf, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;
use tracing::{debug, info};

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
    let ctx = start_default_test_kms_server().await;

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

pub(crate) fn validate_certificate(
    cli_conf_path: &str,
    sub_command: &str,
    certificates: Vec<String>,
    uids: Vec<String>,
    date: Option<String>,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug,cosmian_kms_server=debug");
    let mut args: Vec<String> = vec!["validate".to_owned()];
    for certificate in certificates {
        args.push("--certificate".to_owned());
        args.push(certificate);
    }
    for uid in uids {
        args.push("--unique-identifier".to_owned());
        args.push(uid);
    }
    if let Some(d) = date {
        args.push("--validity-time".to_owned());
        args.push(d);
    }
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let validate_output = std::str::from_utf8(&output.stdout)?;
        return Ok(validate_output.to_string())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_validate_cli() -> Result<(), CliError> {
    let ctx = start_default_test_kms_server().await;

    info!("importing root cert");
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

    info!("importing intermediate cert");
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
    info!("leaf1 cert imported: {leaf1_certificate_id}");

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
    info!("leaf2 cert imported: {leaf2_certificate_id}");

    let test1_res = validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        vec![],
        vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf1_certificate_id,
        ],
        None,
    )?;
    info!(
        "Validate chain with leaf1: result supposed to be invalid, as leaf1 was revoked. \
         test1_res: {test1_res}"
    );
    assert_eq!(test1_res, "Invalid\n");

    let test2_res = validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        vec![],
        vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf2_certificate_id.clone(),
        ],
        None,
    )?;
    info!(
        "validate chain with leaf2: result supposed to be valid, as leaf2 was never revoked. \
         test2_res: {test2_res}"
    );
    assert_eq!("Valid\n", test2_res);

    let test3_res = validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        vec![],
        vec![
            intermediate_certificate_id,
            root_certificate_id.clone(),
            leaf2_certificate_id,
        ],
        // Date: 15/04/2048
        Some("4804152030Z".to_string()),
    )?;
    info!(
        "validate chain with leaf2: result supposed to be invalid, as date is posthumous to \
         leaf2's expiration date. test3_res: {test3_res}"
    );
    assert_eq!(test3_res, "Invalid\n");

    let test4_res = validate_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        vec![],
        vec![root_certificate_id],
        None,
    )?;

    info!("validate chain only. Must be valid.");
    assert_eq!("Valid\n", test4_res);

    info!("validate tests successfully passed");
    Ok(())
}

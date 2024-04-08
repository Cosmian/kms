use std::{
    fs::{self, File},
    io::Read,
    path::PathBuf,
    process::Command,
};

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::{start_default_test_kms_server, ONCE};
use tempfile::TempDir;
use tracing::debug;

use super::SUB_COMMAND;
use crate::{
    actions::certificates::{CertificateExportFormat, CertificateInputFormat},
    error::CliError,
    tests::{
        certificates::{import::import_certificate, openssl::check_certificate},
        shared::locate,
        utils::{extract_uids::extract_uid, recover_cmd_logs},
        PROG_NAME,
    },
};

// if logs are required, declare in bash: `export RUST_LOG="cosmian_kms_server=debug,cosmian_kms_cli=debug"`
pub fn certify(
    cli_conf_path: &str,
    ca: &str,
    subject: Option<String>,
    csr: Option<PathBuf>,
    csr_format: Option<String>,
    tags: &[&str],
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");

    let mut args = vec!["create".to_owned()];
    if let Some(subject) = subject {
        args.push("--subject-common-name".to_owned());
        args.push(subject);
    }
    if let Some(csr) = csr {
        args.push("--certificate-signing-request".to_owned());
        args.push(csr.to_string_lossy().to_string());
        args.push("--certificate-signing-request-format".to_owned());
        args.push(csr_format.unwrap_or_else(|| "pem".to_owned()));
    }
    debug!("certify: tags: {:?}", tags);

    // add tags
    for tag in tags {
        args.push("--tag".to_owned());
        args.push((*tag).to_string());
    }
    args.push(ca.to_string());
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;

        let unique_identifier = extract_uid(output, "The certificate was created with id")
            .ok_or_else(|| {
                CliError::Default("failed extracting the unique identifier".to_owned())
            })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(filename).expect("no file found");
    let metadata = fs::metadata(filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    let _ret = f.read(&mut buffer).expect("buffer overflow");

    buffer
}

#[allow(clippy::too_many_arguments)]
pub fn export(
    cli_conf_path: &str,
    sub_command: &str,
    tags_args: Option<&[&str]>,
    certificate_id: &str,
    certificate_file: &str,
    output_format: CertificateExportFormat,
    wrap_key_id: Option<String>,
    allow_revoked: bool,
) -> Result<(), CliError> {
    let mut args = vec!["export"];
    match tags_args {
        Some(tags) => {
            // add tags
            for tag in tags {
                args.push("--tag");
                args.push(tag);
            }
        }
        None => {
            args.push("--certificate-id");
            args.push(certificate_id);
        }
    };
    args.push(certificate_file);
    match output_format {
        CertificateExportFormat::Pem => {
            args.push("--format");
            args.push("pem");
        }
        CertificateExportFormat::Pkcs12 => {
            args.push("--format");
            args.push("pkcs12");
            args.push("--pkcs12_password");
            args.push("secret");
        }
        CertificateExportFormat::JsonTtlv => {
            args.push("--format");
            args.push("ttlv");
        }
    };
    if let Some(wki) = &wrap_key_id {
        args.push("--wrap-key-id");
        args.push(wki);
    }
    if allow_revoked {
        args.push("--allow-revoked");
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    println!("output: {output:?}");
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub fn revoke(
    cli_conf_path: &str,
    sub_command: &str,
    certificate_id: &str,
    revocation_reason: &str,
) -> Result<(), CliError> {
    let args: Vec<String> = [
        "revoke",
        "--certificate-id",
        certificate_id,
        revocation_reason,
    ]
    .into_iter()
    .map(std::string::ToString::to_string)
    .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub fn destroy(
    cli_conf_path: &str,
    sub_command: &str,
    certificate_id: &str,
) -> Result<(), CliError> {
    let args: Vec<String> = vec!["destroy", "--certificate-id", certificate_id]
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
#[ignore] //This feature will be completely refactored
pub async fn test_certify_with_subject_cn() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();
    // let tmp_path = std::path::Path::new("./");
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    let ca = "RootCA/SubCA";
    let hierarchical_depth = ca.split('/').count();
    let tags = &["certificate"];

    // create, export, check, revoke and destroy
    {
        let subject = "My server".to_owned();
        let certificate_id = certify(
            &ctx.owner_client_conf_path,
            ca,
            Some(subject),
            None,
            None,
            tags,
        )?;

        // Count the number of KMIP objects created
        let ids = locate(&ctx.owner_client_conf_path, Some(tags), None, None, None)?;
        // Expected 3 kmip objects per certificate (including public and private keys):
        // - 1 public key, 1 private key and 1 certificate for the root CA
        // - 1 public key, 1 private key and 1 certificate for the sub CA
        // - 1 public key, 1 private key and 1 certificate for the leaf certificate
        assert_eq!(ids.len(), 3 * (hierarchical_depth + 1));

        // create another certificate (CA root already created)
        debug!("\n\n\ntest_certify: create another certificate");
        {
            let subject = "My server Number 2".to_owned();
            let _certificate_id = certify(
                &ctx.owner_client_conf_path,
                ca,
                Some(subject),
                None,
                None,
                tags,
            )?;
        }

        let ids = locate(&ctx.owner_client_conf_path, Some(tags), None, None, None)?;
        // Expected 3 more kmip objects:
        // - 1 public key, 1 private key and 1 certificate for this new certificate
        assert_eq!(ids.len(), 3 * (hierarchical_depth + 2));

        // Export certificate as PKCS12
        debug!("\n\n\ntest_certify: export");
        let export_filename = tmp_path.join("output.p12").to_str().unwrap().to_owned();
        export(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            None,
            &certificate_id,
            &export_filename,
            CertificateExportFormat::Pkcs12,
            None,
            false,
        )?;
        // Read the bytes of the file and check them with openssl
        let certificate_bytes = get_file_as_byte_vec(&export_filename);
        check_certificate(&certificate_bytes, "secret");

        // Export certificate as PEM only
        let export_filename = tmp_path.join("cert.pem").to_str().unwrap().to_owned();
        export(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            None,
            &certificate_id,
            &export_filename,
            CertificateExportFormat::Pem,
            None,
            false,
        )?;
        let certificate_bytes = get_file_as_byte_vec(&export_filename);
        let certificate_str = std::str::from_utf8(&certificate_bytes).unwrap();
        println!("Certificate PEM: {certificate_str}");

        // Export certificate as RAW KMIP TTLV
        let export_filename = tmp_path.join("ttlv.json").to_str().unwrap().to_owned();
        export(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            None,
            &certificate_id,
            &export_filename,
            CertificateExportFormat::JsonTtlv,
            None,
            false,
        )?;

        // Export root CA certificate as PEM only
        let export_filename = tmp_path.join("root.pem").to_str().unwrap().to_owned();
        export(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            Some(&["_cert", "_cert_ca=RootCA"]),
            &certificate_id,
            &export_filename,
            CertificateExportFormat::Pem,
            None,
            false,
        )?;
        let certificate_bytes = get_file_as_byte_vec(&export_filename);
        let certificate_str = std::str::from_utf8(&certificate_bytes).unwrap();
        println!("CA ROOT PEM: {certificate_str}");

        // Export sub CA certificate as PEM only
        let export_filename = tmp_path.join("subca.pem").to_str().unwrap().to_owned();
        export(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            Some(&["_cert", "_cert_ca=SubCA"]),
            &certificate_id,
            &export_filename,
            CertificateExportFormat::Pem,
            None,
            false,
        )?;
        let certificate_bytes = get_file_as_byte_vec(&export_filename);
        let certificate_str = std::str::from_utf8(&certificate_bytes).unwrap();
        println!("CA SubCA PEM: {certificate_str}");

        // Revoke it
        revoke(
            &ctx.owner_client_conf_path,
            SUB_COMMAND,
            &certificate_id,
            "cert revocation test",
        )?;
        destroy(&ctx.owner_client_conf_path, SUB_COMMAND, &certificate_id).unwrap();
    }

    Ok(())
}

#[tokio::test]
#[ignore] //This feature will be completely refactored
pub async fn test_certify_with_csr() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let _tmp_path = tmp_dir.into_path();
    // let tmp_path = std::path::Path::new("./");
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    let ca = "RootCA/SubCA";
    let _hierarchical_depth = ca.split('/').count();
    let tags = &["certificate"];

    // import the intermediate certificate
    {
        import_certificate(
            &ctx.owner_client_conf_path,
            "certificates",
            "test_data/certificates/csr/intermediate.p12",
            CertificateInputFormat::Pkcs12,
            None,
            Some("intermediate".to_string()),
            None,
            None,
            Some(&["import_pkcs12"]),
            None,
            false,
            true,
        )?;
    }

    let csr = PathBuf::from("test_data/certificates/csr/csr_wikipedia.pem");

    // create, export, check, revoke and destroy
    {
        let _subject = "My server";
        let _certificate_id = certify(
            &ctx.owner_client_conf_path,
            ca,
            None,
            Some(csr),
            Some("pem".to_string()),
            tags,
        )?;
    }

    Ok(())
}

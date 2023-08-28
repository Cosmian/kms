use std::{
    fs::{self, File},
    io::Read,
    process::Command,
};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use tracing::debug;

use super::{openssl::check_certificate, SUB_COMMAND};
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        shared::locate,
        utils::{extract_uids::extract_uid, init_test_server, ONCE},
        PROG_NAME,
    },
};

// if logs are required, declare in bash: `export RUST_LOG="cosmian_kms_server=debug,cosmian_kms_cli=debug"`
pub fn certify(
    cli_conf_path: &str,
    ca: &str,
    subject: &str,
    tags: &[&str],
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args = vec!["certificates", "create"];

    args.extend(vec!["--ca", ca]);
    args.extend(vec!["--subject", subject]);

    debug!("certify: tags: {:?}", tags);

    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg(SUB_COMMAND).args(args);

    let output = cmd.output()?;
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

// pub fn locate(
//     cli_conf_path: &str,
//     tags: Option<&[&str]>,
//     algorithm: Option<&str>,
//     cryptographic_length: Option<usize>,
//     key_format_type: Option<&str>,
// ) -> Result<Vec<String>, CliError> {
//     let mut args: Vec<String> = vec![];
//     if let Some(tags) = tags {
//         for tag in tags {
//             args.push("--tag".to_owned());
//             args.push((*tag).to_string());
//         }
//     }
//     if let Some(algorithm) = algorithm {
//         args.push("--algorithm".to_owned());
//         args.push(algorithm.to_owned());
//     }
//     if let Some(cryptographic_length) = cryptographic_length {
//         args.push("--cryptographic-length".to_owned());
//         args.push(cryptographic_length.to_string());
//     }
//     if let Some(key_format_type) = key_format_type {
//         args.push("--key-format-type".to_owned());
//         args.push(key_format_type.to_string());
//     }

//     let mut cmd = Command::cargo_bin(PROG_NAME)?;
//     cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
//     cmd.arg("locate").args(args);
//     let output = cmd.output()?;
//     if output.status.success() {
//         return Ok(std::str::from_utf8(&output.stdout)?
//             .lines()
//             .map(std::borrow::ToOwned::to_owned)
//             .collect::<Vec<String>>())
//     }
//     Err(CliError::Default(
//         std::str::from_utf8(&output.stderr)?.to_owned(),
//     ))
// }

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
    certificate_id: &str,
    certificate_file: &str,
    bytes: bool,
    allow_revoked: bool,
) -> Result<(), CliError> {
    let mut args: Vec<String> = [
        "certificates",
        "export",
        "--certificate-id",
        certificate_id,
        certificate_file,
    ]
    .into_iter()
    .map(std::string::ToString::to_string)
    .collect();
    if bytes {
        args.push("--bytes".to_owned());
    }
    if allow_revoked {
        args.push("--allow-revoked".to_owned());
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
        "certificates",
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
    let args: Vec<String> = vec![
        "certificates",
        "destroy",
        "--certificate-id",
        certificate_id,
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

#[tokio::test]
pub async fn test_certify() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();
    let ctx = ONCE.get_or_init(init_test_server).await;
    // let ca = "CA";
    let ca = "CA/SubCA1";
    // let ca = "CA/SubCA1/SubCA2/SubCA3";
    let tags = &["certificate"];

    // create, export, check, revoke and destroy
    {
        let subject = "My server";
        let certificate_id = certify(&ctx.owner_cli_conf_path, ca, subject, tags)?;

        // Count the number of KMIP objects created
        let ids = locate(&ctx.owner_cli_conf_path, Some(tags), None, None, None)?;
        // Expected 9 kmip objects for this tag:
        // - 1 public key, 1 private key and 1 certificate for the root CA
        // - 1 public key, 1 private key and 1 certificate for the sub CA
        // - 1 public key, 1 private key and 1 certificate for the leaf certificate
        assert_eq!(ids.len(), 9);

        // create another certificate (CA root already created)
        debug!("\n\n\ntest_certify: create another certificate");
        {
            let subject = "My server Number 2";
            let _certificate_id = certify(&ctx.owner_cli_conf_path, ca, subject, tags)?;
        }

        let ids = locate(&ctx.owner_cli_conf_path, Some(tags), None, None, None)?;
        // Expected 12 kmip objects for this tag (3 more):
        // - already 9 kmip objects created above
        // - 1 public key, 1 private key and 1 certificate for the leaf certificate
        assert_eq!(ids.len(), 12);

        // Export
        let export_filename = tmp_path.join("output.export").to_str().unwrap().to_owned();
        export(
            &ctx.owner_cli_conf_path,
            "pki",
            &certificate_id,
            &export_filename,
            true,
            false,
        )?;
        // Read the bytes of the file and check them with openssl
        let certificate_bytes = get_file_as_byte_vec(&export_filename);
        check_certificate(&certificate_bytes);

        // Revoke it
        revoke(
            &ctx.owner_cli_conf_path,
            "pki",
            &certificate_id,
            "cert revocation test",
        )?;
        destroy(&ctx.owner_cli_conf_path, "pki", &certificate_id).unwrap();
    }

    Ok(())
}

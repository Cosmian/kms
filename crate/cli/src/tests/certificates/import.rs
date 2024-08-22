use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;

use crate::{
    actions::{certificates::CertificateInputFormat, shared::utils::KeyUsage},
    error::{result::CliResult, CliError},
    tests::{
        utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        PROG_NAME,
    },
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn import_certificate(
    cli_conf_path: &str,
    sub_command: &str,
    key_file: &str,
    format: &CertificateInputFormat,
    pkcs12_password: Option<&str>,
    certificate_id: Option<String>,
    private_key_id: Option<String>,
    issuer_certificate_id: Option<String>,
    tags: Option<&[&str]>,
    key_usage_vec: Option<Vec<KeyUsage>>,
    unwrap: bool,
    replace_existing: bool,
) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args: Vec<String> = vec!["import".to_owned(), key_file.to_owned()];
    if let Some(key_id) = certificate_id {
        args.push(key_id);
    }
    if unwrap {
        args.push("-u".to_owned());
    }
    if replace_existing {
        args.push("-r".to_owned());
    }
    // Format arg
    args.push("-f".to_owned());
    match format {
        CertificateInputFormat::JsonTtlv => args.push("json-ttlv".to_owned()),
        CertificateInputFormat::Pem => args.push("pem".to_owned()),
        CertificateInputFormat::Der => args.push("der".to_owned()),
        CertificateInputFormat::Chain => args.push("chain".to_owned()),
        CertificateInputFormat::CCADB => args.push("ccadb".to_owned()),
        CertificateInputFormat::Pkcs12 => {
            args.push("pkcs12".to_owned());
            args.push("--pkcs12-password".to_owned());
            args.push(pkcs12_password.unwrap_or("").to_owned());
        }
    };
    if let Some(key_usage_vec) = key_usage_vec {
        for key_usage in key_usage_vec {
            args.push("--key-usage".to_owned());
            args.push(key_usage.into());
        }
    }
    if let Some(tags) = tags {
        for tag in tags {
            args.push("--tag".to_owned());
            args.push((*tag).to_string());
        }
    }
    if let Some(key_id) = private_key_id {
        args.push("--private-key-id".to_owned());
        args.push(key_id);
    }
    if let Some(certificate_id) = issuer_certificate_id {
        args.push("--issuer-certificate-id".to_owned());
        args.push(certificate_id);
    }
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_unique_identifier(import_output)
            .ok_or_else(|| CliError::Default("failed extracting the imported key id".to_owned()))?
            .to_owned();
        return Ok(imported_key_id)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

// #[tokio::test]
// pub async fn test_certificate_import_different_format() -> CliResult<()> {
//     // Create a test server
//     let ctx = start_default_test_kms_server().await;
//     // import as TTLV JSON
//     import_certificate(
//         &ctx.owner_client_conf_path,
//         "certificates",
//         "test_data/certificates/exported_certificate_ttlv.json",
//         CertificateInputFormat::JsonTtlv,
//         None,
//         Some("ttlv_cert".to_string()),
//         None,
//         None,
//         None,
//         None,
//         false,
//         true,
//     )?;

//     // import as PEM
//     import_certificate(
//         &ctx.owner_client_conf_path,
//         "certificates",
//         "test_data/certificates/ca.crt",
//         CertificateInputFormat::Pem,
//         None,
//         Some("pem_cert".to_string()),
//         None,
//         None,
//         Some(&["import_cert"]),
//         None,
//         false,
//         true,
//     )?;

//     // import a chain
//     import_certificate(
//         &ctx.owner_client_conf_path,
//         "certificates",
//         "test_data/certificates/mozilla_IncludedRootsPEM.txt",
//         CertificateInputFormat::Chain,
//         None,
//         Some("chain_cert".to_string()),
//         None,
//         None,
//         Some(&["import_chain"]),
//         None,
//         false,
//         true,
//     )?;

//     // import a PKCS12
//     import_certificate(
//         &ctx.owner_client_conf_path,
//         "certificates",
//         "test_data/certificates/p12/output.p12",
//         CertificateInputFormat::Pkcs12,
//         Some("secret"),
//         Some("p12_cert".to_string()),
//         None,
//         None,
//         Some(&["import_pkcs12"]),
//         None,
//         false,
//         true,
//     )?;

//     Ok(())
// }

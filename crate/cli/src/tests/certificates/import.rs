use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;

use crate::{
    actions::{certificates::CertificateInputFormat, shared::utils::KeyUsage},
    error::{result::CliResult, CliError},
    tests::{
        utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        PROG_NAME,
    },
};

#[derive(Debug)]
pub(crate) struct ImportCertificateInput<'a> {
    pub(crate) cli_conf_path: &'a str,
    pub(crate) sub_command: &'a str,
    pub(crate) key_file: &'a str,
    pub(crate) format: &'a CertificateInputFormat,
    pub(crate) pkcs12_password: Option<&'a str>,
    pub(crate) certificate_id: Option<String>,
    pub(crate) private_key_id: Option<String>,
    pub(crate) issuer_certificate_id: Option<String>,
    pub(crate) tags: Option<&'a [&'a str]>,
    pub(crate) key_usage_vec: Option<Vec<KeyUsage>>,
    pub(crate) unwrap: bool,
    pub(crate) replace_existing: bool,
}

impl Default for ImportCertificateInput<'_> {
    fn default() -> Self {
        Self {
            cli_conf_path: "",
            sub_command: "",
            key_file: "",
            format: &CertificateInputFormat::JsonTtlv,
            pkcs12_password: None,
            certificate_id: None,
            private_key_id: None,
            issuer_certificate_id: None,
            tags: None,
            key_usage_vec: None,
            unwrap: false,
            replace_existing: false,
        }
    }
}

pub(crate) fn import_certificate(
    import_certificate_input: ImportCertificateInput,
) -> CliResult<String> {
    let ImportCertificateInput {
        cli_conf_path,
        sub_command,
        key_file,
        format,
        pkcs12_password,
        certificate_id,
        private_key_id,
        issuer_certificate_id,
        tags,
        key_usage_vec,
        unwrap,
        replace_existing,
    } = import_certificate_input;
    let mut cmd = Command::cargo_bin(PROG_NAME).unwrap();
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

#[tokio::test]
async fn test_certificate_import_different_format() -> CliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // import as TTLV JSON
    import_certificate(ImportCertificateInput {
        cli_conf_path: &ctx.owner_client_conf_path,
        sub_command: "certificates",
        key_file: "test_data/certificates/exported_certificate_ttlv.json",
        format: &CertificateInputFormat::JsonTtlv,
        pkcs12_password: None,
        certificate_id: None,
        private_key_id: None,
        issuer_certificate_id: None,
        tags: None,
        key_usage_vec: None,
        unwrap: false,
        replace_existing: true,
    })?;

    // import as PEM
    import_certificate(ImportCertificateInput {
        cli_conf_path: &ctx.owner_client_conf_path,
        sub_command: "certificates",
        key_file: "test_data/certificates/ca.crt",
        format: &CertificateInputFormat::Pem,
        pkcs12_password: None,
        certificate_id: None,
        private_key_id: None,
        issuer_certificate_id: None,
        tags: None,
        key_usage_vec: None,
        unwrap: false,
        replace_existing: true,
    })?;

    // import a chain
    import_certificate(ImportCertificateInput {
        cli_conf_path: &ctx.owner_client_conf_path,
        sub_command: "certificates",
        key_file: "test_data/certificates/mozilla_IncludedRootsPEM.txt",
        format: &CertificateInputFormat::Chain,
        pkcs12_password: None,
        certificate_id: None,
        private_key_id: None,
        issuer_certificate_id: None,
        tags: Some(&["import_chain"]),
        key_usage_vec: None,
        unwrap: false,
        replace_existing: true,
    })?;

    // import a PKCS12
    import_certificate(ImportCertificateInput {
        cli_conf_path: &ctx.owner_client_conf_path,
        sub_command: "certificates",
        key_file: "test_data/certificates/p12/output.p12",
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: None,
        private_key_id: None,
        issuer_certificate_id: None,
        tags: Some(&["import_pkcs12"]),
        key_usage_vec: None,
        unwrap: false,
        replace_existing: true,
    })?;

    Ok(())
}

use std::{collections::HashMap, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;

use crate::{
    actions::shared::AttributeTag,
    config::KMS_CLI_CONF_ENV,
    error::{result::CliResultHelper, CliError},
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

pub fn get_attributes(
    cli_conf_path: &str,
    sub_command: &str,
    uid: &str,
    attribute_tags: &[AttributeTag],
) -> Result<HashMap<AttributeTag, Value>, CliError> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let mut args: Vec<String> = [
        "get-attributes",
        "--id",
        uid,
        "--output-file",
        temp_file
            .path()
            .to_str()
            .context("failed converting path to string")?,
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();

    for tag in attribute_tags {
        args.push("--attribute".to_owned());
        let arg_value = match tag {
            AttributeTag::ActivationDate => "activation-date",
            AttributeTag::CryptographicAlgorithm => "cryptographic-algorithm",
            AttributeTag::CryptographicLength => "cryptographic-length",
            AttributeTag::CryptographicParameters => "cryptographic-parameters",
            AttributeTag::CryptographicUsageMask => "cryptographic-usage-mask",
            AttributeTag::KeyFormatType => "key-format-type",
            AttributeTag::LinkedPrivateKeyId => "linked-private-key-id",
            AttributeTag::LinkedPublicKeyId => "linked-public-key-id",
            AttributeTag::LinkedIssuerCertificateId => "linked-issuer-certificate-id",
            AttributeTag::LinkedCertificateId => "linked-certificate-id",
        };
        args.push(arg_value.to_owned());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug,cosmian_kms_server=trace");
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::fs::read_to_string(temp_file.path())?;
        let output: HashMap<String, Value> = serde_json::from_str(&output)?;
        let mut result = HashMap::with_capacity(output.len());
        for (k, v) in output {
            let tag = match k.as_str() {
                "activation-date" => AttributeTag::ActivationDate,
                "cryptographic-algorithm" => AttributeTag::CryptographicAlgorithm,
                "cryptographic-length" => AttributeTag::CryptographicLength,
                "cryptographic-parameters" => AttributeTag::CryptographicParameters,
                "cryptographic-usage-mask" => AttributeTag::CryptographicUsageMask,
                "key-format-type" => AttributeTag::KeyFormatType,
                "linked-private-key-id" => AttributeTag::LinkedPrivateKeyId,
                "linked-public-key-id" => AttributeTag::LinkedPublicKeyId,
                "linked-issuer-certificate-id" => AttributeTag::LinkedIssuerCertificateId,
                "linked-certificate-id" => AttributeTag::LinkedCertificateId,
                _ => return Err(CliError::Default(format!("unknown attribute tag: {}", k))),
            };
            result.insert(tag, v);
        }
        return Ok(result)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::KMS_CLI_CONF_ENV;

use crate::{
    actions::attributes::SetOrDeleteAttributes,
    error::{result::CliResult, CliError},
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

pub(crate) fn prepare_attributes(
    subcommand: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> Vec<std::string::String> {
    let mut args = vec![subcommand.to_owned()];

    if let Some(id) = &requested_attributes.id {
        args.push("--id".to_owned());
        args.push(id.clone());
    }
    if let Some(date) = requested_attributes.activation_date {
        args.push("--activation-date".to_owned());
        args.push(date.to_string());
    }

    if let Some(cryptographic_algorithm) = requested_attributes.cryptographic_algorithm {
        args.push("--cryptographic-algorithm".to_owned());
        args.push(cryptographic_algorithm.to_string());
    }
    if let Some(cryptographic_length) = requested_attributes.cryptographic_length {
        args.push("--cryptographic-length".to_owned());
        args.push(cryptographic_length.to_string());
    }

    if let Some(key_usage_vec) = &requested_attributes.key_usage {
        for usage in key_usage_vec {
            args.push("--key-usage".to_owned());
            args.push(usage.clone().into());
        }
    }

    if let Some(public_key_id) = &requested_attributes.public_key_id {
        args.push("--public-key-id".to_owned());
        args.push(public_key_id.clone());
    }

    if let Some(private_key_id) = &requested_attributes.private_key_id {
        args.push("--private-key-id".to_owned());
        args.push(private_key_id.clone());
    }

    if let Some(certificate_id) = &requested_attributes.certificate_id {
        args.push("--certificate-id".to_owned());
        args.push(certificate_id.clone());
    }

    if let Some(pkcs12_certificate_id) = &requested_attributes.pkcs12_certificate_id {
        args.push("--p12-id".to_owned());
        args.push(pkcs12_certificate_id.clone());
    }

    if let Some(pkcs12_password_certificate) = &requested_attributes.pkcs12_password_certificate {
        args.push("--p12-pwd".to_owned());
        args.push(pkcs12_password_certificate.clone());
    }

    if let Some(parent_id) = &requested_attributes.parent_id {
        args.push("--parent-id".to_owned());
        args.push(parent_id.clone());
    }

    if let Some(child_id) = &requested_attributes.child_id {
        args.push("--child-id".to_owned());
        args.push(child_id.clone());
    }

    if let Some(tags) = &requested_attributes.tags {
        for tag in tags {
            args.push("--tag".to_owned());
            args.push(tag.clone());
        }
    }

    if let Some(vendor_attributes) = &requested_attributes.vendor_attributes {
        if let Some(vendor_identification) = &vendor_attributes.vendor_identification {
            args.push("--vendor-identification".to_owned());
            args.push(vendor_identification.clone());
        }
        if let Some(attribute_name) = &vendor_attributes.attribute_name {
            args.push("--attribute-name".to_owned());
            args.push(attribute_name.clone());
        }
        if let Some(attribute_value) = &vendor_attributes.attribute_value {
            args.push("--attribute-value".to_owned());
            args.push(attribute_value.clone());
        }
    }

    args
}

pub(crate) fn set_attributes(
    cli_conf_path: &str,
    requested_attributes: &SetOrDeleteAttributes,
) -> CliResult<String> {
    let args = prepare_attributes("set", requested_attributes);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("attributes").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let set_attribute_output = std::str::from_utf8(&output.stdout)?;
        return Ok(set_attribute_output.to_string())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

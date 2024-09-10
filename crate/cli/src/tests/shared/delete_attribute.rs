use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::{kmip::kmip_types::Tag, KMS_CLI_CONF_ENV};

use super::set_attribute::prepare_attributes;
use crate::{
    actions::shared::CommonAttributes,
    error::{result::CliResult, CliError},
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

pub(crate) fn delete_attributes(
    cli_conf_path: &str,
    common_attributes: &Option<CommonAttributes>,
    attribute_references: Option<Vec<Tag>>,
) -> CliResult<String> {
    let mut args = common_attributes
        .as_ref()
        .map_or_else(Vec::<String>::new, |common_attributes| {
            prepare_attributes(common_attributes)
        });

    if let Some(references) = attribute_references {
        for reference in references {
            args.push("--attribute".to_owned());
            args.push(reference.to_string());
        }
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("delete-attributes").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let set_attribute_output = std::str::from_utf8(&output.stdout)?;
        return Ok(set_attribute_output.to_string())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

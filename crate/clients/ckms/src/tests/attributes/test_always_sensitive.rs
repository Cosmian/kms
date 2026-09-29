//! End-to-end CLI tests for the server-managed `AlwaysSensitive` attribute
//! (KMIP 2.1 §4.3).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_types::Tag;
use tempfile::NamedTempFile;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        symmetric::create_key::create_symmetric_key,
        utils::{ckms_bin, owner_config, recover_cmd_logs},
    },
};

/// Return the `AlwaysSensitive` value reported by `ckms attributes get`.
fn get_always_sensitive(cli_conf_path: &str, key_id: &str) -> CosmianResult<Option<bool>> {
    let output_file = NamedTempFile::new()?;
    let output_path = output_file.path().to_string_lossy().to_string();

    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args([
        "get",
        "--id",
        key_id,
        "--attribute",
        &Tag::AlwaysSensitive.to_string(),
        "--output-file",
        &output_path,
    ]);
    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ));
    }

    let contents = std::fs::read_to_string(output_file.path())?;
    let json: serde_json::Value = serde_json::from_str(&contents)?;
    Ok(json
        .get(Tag::AlwaysSensitive.to_string())
        .and_then(serde_json::Value::as_bool))
}

/// Run `ckms attributes set` and return whether it succeeded.
fn set_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> bool {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["set", "--id", key_id];
    args.extend(extra_args);
    cmd.arg(SUB_COMMAND).args(args);
    recover_cmd_logs(&mut cmd).status.success()
}

/// Run `ckms attributes delete` and return whether it succeeded.
fn delete_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> bool {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["delete", "--id", key_id];
    args.extend(extra_args);
    cmd.arg(SUB_COMMAND).args(args);
    recover_cmd_logs(&mut cmd).status.success()
}

/// A sensitive key reports `AlwaysSensitive = true`; a plain key reports `false`.
#[tokio::test]
async fn test_always_sensitive_reported_at_creation() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let sensitive_id = create_symmetric_key(&owner_conf, &["--sensitive"])?;
    assert_eq!(
        get_always_sensitive(&owner_conf, &sensitive_id)?,
        Some(true),
        "sensitive key must report AlwaysSensitive = true"
    );

    let plain_id = create_symmetric_key(&owner_conf, &[])?;
    assert_eq!(
        get_always_sensitive(&owner_conf, &plain_id)?,
        Some(false),
        "non-sensitive key must report AlwaysSensitive = false"
    );

    Ok(())
}

/// Setting `Sensitive = false` permanently clears `AlwaysSensitive`, even after
/// it is set back to `true`.
#[tokio::test]
async fn test_always_sensitive_flips_on_sensitive_change() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let key_id = create_symmetric_key(&owner_conf, &["--sensitive"])?;
    assert_eq!(get_always_sensitive(&owner_conf, &key_id)?, Some(true));

    assert!(set_attribute(
        &owner_conf,
        &key_id,
        &["--sensitive", "false"]
    ));
    assert_eq!(
        get_always_sensitive(&owner_conf, &key_id)?,
        Some(false),
        "AlwaysSensitive must become false once Sensitive is set to false"
    );

    assert!(set_attribute(
        &owner_conf,
        &key_id,
        &["--sensitive", "true"]
    ));
    assert_eq!(
        get_always_sensitive(&owner_conf, &key_id)?,
        Some(false),
        "AlwaysSensitive must stay false after Sensitive is set back to true"
    );

    Ok(())
}

/// `AlwaysSensitive` is server-managed and cannot be deleted by the client.
#[tokio::test]
async fn test_always_sensitive_cannot_be_deleted() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let key_id = create_symmetric_key(&owner_conf, &["--sensitive"])?;
    assert!(
        !delete_attribute(
            &owner_conf,
            &key_id,
            &["--attribute", &Tag::AlwaysSensitive.to_string()],
        ),
        "deleting AlwaysSensitive must be rejected by the server"
    );
    assert_eq!(
        get_always_sensitive(&owner_conf, &key_id)?,
        Some(true),
        "AlwaysSensitive must be unchanged after a rejected delete"
    );

    Ok(())
}

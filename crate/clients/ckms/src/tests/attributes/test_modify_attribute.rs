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

/// Set an attribute on a KMS object via the ckms binary.
fn set_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["set".to_owned(), "--id".to_owned(), key_id.to_owned()];
    args.extend(extra_args.iter().map(|s| (*s).to_owned()));
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Modify an attribute on a KMS object via the ckms binary.
fn modify_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["modify".to_owned(), "--id".to_owned(), key_id.to_owned()];
    args.extend(extra_args.iter().map(|s| (*s).to_owned()));
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_modify_attribute() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_conf, &[])?;

    // Use Name: KMIP 1.4 §3.2 / KMIP 2.1 §4.34 mark it "Modifiable by client: Yes"
    // and it carries no key-lifecycle constraint. Server-managed attributes such
    // as Cryptographic Length (KMIP 2.1 §4.15 Table 57, "Modifiable by client:
    // No") are rejected by ModifyAttribute and cannot be used here.
    set_attribute(&owner_conf, &key_id, &["--name", "modify-attr-initial"])?;

    // Modify the name
    modify_attribute(&owner_conf, &key_id, &["--name", "modify-attr-updated"])?;

    Ok(())
}

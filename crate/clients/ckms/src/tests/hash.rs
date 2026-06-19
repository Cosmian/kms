use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{extract_uids::extract_uid, owner_config, run_ckms},
};

/// Compute a hash via the CLI.
///
/// `extra_args` are appended after `["hash"]`.
pub(crate) fn create_hash(cli_conf_path: &str, extra_args: &[&str]) -> CosmianResult<String> {
    let mut args = vec!["hash"];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    let uid = extract_uid(&stdout, "Hash output").ok_or_else(|| {
        crate::error::CosmianError::Default("failed extracting the unique identifier".to_owned())
    })?;
    Ok(uid.to_string())
}

#[tokio::test]
pub(crate) async fn test_hash() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    create_hash(
        &owner_client_conf_path,
        &["--algorithm", "sha3-256", "--data", "010203"],
    )?;

    Ok(())
}

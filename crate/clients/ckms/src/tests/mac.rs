use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        symmetric::create_key::create_symmetric_key,
        utils::{extract_uids::extract_uid, owner_config, run_ckms},
    },
};

/// Compute a MAC via the CLI.
///
/// `extra_args` are appended after `["mac", "compute"]`.
pub(crate) fn create_mac(cli_conf_path: &str, extra_args: &[&str]) -> CosmianResult<String> {
    let mut args = vec!["mac", "compute"];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    let uid = extract_uid(&stdout, "Mac output").ok_or_else(|| {
        crate::error::CosmianError::Default("failed extracting the unique identifier".to_owned())
    })?;
    Ok(uid.to_string())
}

#[tokio::test]
pub(crate) async fn test_mac() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--algorithm", "sha3", "--number-of-bits", "256"],
    )?;

    let large_data = "00".repeat(1024);

    create_mac(
        &owner_client_conf_path,
        &[
            "--mac-key-id",
            &mac_key_id,
            "--algorithm",
            "sha3-256",
            "--data",
            &large_data,
        ],
    )?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_sha1() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--algorithm", "sha3", "--number-of-bits", "256"],
    )?;

    let data = "00".repeat(64);

    create_mac(
        &owner_client_conf_path,
        &[
            "--mac-key-id",
            &mac_key_id,
            "--algorithm",
            "sha1",
            "--data",
            &data,
        ],
    )?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_sha224() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--algorithm", "sha3", "--number-of-bits", "256"],
    )?;

    let data = "00".repeat(64);

    create_mac(
        &owner_client_conf_path,
        &[
            "--mac-key-id",
            &mac_key_id,
            "--algorithm",
            "sha224",
            "--data",
            &data,
        ],
    )?;

    Ok(())
}

/// Verify a MAC via the CLI
fn verify_mac(
    cli_conf_path: &str,
    mac_key_id: &str,
    algorithm: &str,
    data_hex: &str,
    mac_hex: &str,
) -> CosmianResult<()> {
    run_ckms(
        cli_conf_path,
        &[
            "mac",
            "verify",
            "--mac-key-id",
            mac_key_id,
            "--algorithm",
            algorithm,
            "--data",
            data_hex,
            "--mac",
            mac_hex,
        ],
    )?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_verify() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mac_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--algorithm", "sha3", "--number-of-bits", "256"],
    )?;

    let data_hex = "01".repeat(64);

    // Compute MAC
    let mac_hex = create_mac(
        &owner_client_conf_path,
        &[
            "--mac-key-id",
            &mac_key_id,
            "--algorithm",
            "sha3-256",
            "--data",
            &data_hex,
        ],
    )?;

    // Verify MAC
    verify_mac(
        &owner_client_conf_path,
        &mac_key_id,
        "sha3-256",
        &data_hex,
        &mac_hex,
    )?;

    Ok(())
}

use cosmian_kms_cli_actions::reexport::{
    cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::{
        ImportKeyFormat, KeyUsage,
    },
    cosmian_kms_crypto::{
        crypto::KmsRng, reexport::cosmian_crypto_core::reexport::rand_core::RngCore,
    },
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        shared::{ImportKeyParams, import_key},
        symmetric::create_key::create_symmetric_key,
        utils::{extract_uids::extract_uid, owner_config, run_ckms},
    },
};

/// Import a random AES key of `bytes` bytes carrying the MAC Generate / MAC Verify usage bits
/// (keys from `sym keys create` do not have them).
fn import_aes_mac_key(cli_conf_path: &str, bytes: usize) -> CosmianResult<String> {
    let mut key = vec![0_u8; bytes];
    KmsRng::new().seeded_csrng()?.fill_bytes(&mut key);
    let tmp_dir = TempDir::new()?;
    let key_file = tmp_dir.path().join("mac_key.bin");
    std::fs::write(&key_file, &key)?;
    import_key(ImportKeyParams {
        cli_conf_path: cli_conf_path.to_owned(),
        sub_command: "sym".to_owned(),
        key_file: key_file.to_string_lossy().into_owned(),
        key_format: Some(ImportKeyFormat::Aes),
        key_usage_vec: Some(vec![KeyUsage::MACGenerate, KeyUsage::MACVerify]),
        ..Default::default()
    })
}

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
    Ok(uid.to_owned())
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

/// Run `mac verify` with a mode and return stdout.
fn verify_mac_mode(
    cli_conf_path: &str,
    mac_key_id: &str,
    mode: &str,
    data_hex: &str,
    mac_hex: &str,
) -> CosmianResult<String> {
    run_ckms(
        cli_conf_path,
        &[
            "mac", "verify", "-k", mac_key_id, "--mode", mode, "-d", data_hex, "-m", mac_hex,
        ],
    )
}

#[tokio::test]
pub(crate) async fn test_mac_cmac() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let key = import_aes_mac_key(&conf, 16)?;
    let data = "01".repeat(40);

    let mac = create_mac(&conf, &["-k", &key, "--mode", "cmac", "-d", &data])?;
    assert_eq!(mac.len(), 32, "CMAC tag is 16 bytes");
    let out = verify_mac_mode(&conf, &key, "cmac", &data, &mac)?;
    assert!(out.contains("Valid"), "{out}");

    // change the first hex digit of the tag
    let first = if mac.starts_with('0') { '1' } else { '0' };
    let tampered = format!("{first}{}", &mac[1..]);
    let out = verify_mac_mode(&conf, &key, "cmac", &data, &tampered)?;
    assert!(out.contains("Invalid"), "{out}");
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_gmac() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let key = import_aes_mac_key(&conf, 32)?;
    let data = "02".repeat(40);

    let mac = create_mac(&conf, &["-k", &key, "--mode", "gmac", "-d", &data])?;
    assert_eq!(mac.len(), 56, "GMAC output is IV(12) || tag(16)");
    let out = verify_mac_mode(&conf, &key, "gmac", &data, &mac)?;
    assert!(out.contains("Valid"), "{out}");
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mac_mode_argument_errors() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let key = import_aes_mac_key(&conf, 32)?;
    let data = "03".repeat(16);

    // a hash is not allowed with cmac
    create_mac(
        &conf,
        &["-k", &key, "--mode", "cmac", "-a", "sha256", "-d", &data],
    )
    .unwrap_err();
    // a hash is required with hmac
    create_mac(&conf, &["-k", &key, "-d", &data]).unwrap_err();
    Ok(())
}

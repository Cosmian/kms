use std::{path::Path, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            utils::{
                extract_uids::{extract_private_key, extract_public_key},
                recover_cmd_logs,
            },
        },
        save_kms_cli_config,
    },
};

pub(crate) const SUB_COMMAND: &str = "kem";

/// Create a configurable KEM key pair and return the (`private_key_id`, `public_key_id`).
pub(crate) fn create_kem_key_pair(
    cli_conf_path: &str,
    kem_algorithm: &str,
    tags: &[&str],
) -> CosmianResult<(String, String)> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["key-gen", "--kem", kem_algorithm];
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout_str = std::str::from_utf8(&output.stdout)?;
        let private_key_id = extract_private_key(stdout_str)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the private key id".to_owned())
            })?
            .to_owned();
        let public_key_id = extract_public_key(stdout_str)
            .ok_or_else(|| CosmianError::Default("failed extracting the public key id".to_owned()))?
            .to_owned();
        return Ok((private_key_id, public_key_id));
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Encapsulate using the given public key. Writes the encapsulation to `output_file`.
pub(crate) fn encaps(
    cli_conf_path: &str,
    public_key_id: &str,
    output_file: &Path,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let output_file_str = output_file.to_str().unwrap();
    let args = vec!["encrypt", "--key-id", public_key_id, "-o", output_file_str];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Decapsulate using the given private key. Reads encapsulation from `input_file`,
/// writes the session key to `output_file`.
pub(crate) fn decaps(
    cli_conf_path: &str,
    private_key_id: &str,
    input_file: &Path,
    output_file: &Path,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let input_file_str = input_file.to_str().unwrap();
    let output_file_str = output_file.to_str().unwrap();
    let args = vec![
        "decrypt",
        "--key-id",
        private_key_id,
        input_file_str,
        "-o",
        output_file_str,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn test_kem(cli_conf_path: &str, name: &str, kem_algorithm: &str) -> CosmianResult<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let encapsulation_file = tmp_path.join("encapsulation.enc");
    let session_key_file = tmp_path.join("session_key.plain");

    // Key generation
    let (dk_id, ek_id) = create_kem_key_pair(cli_conf_path, kem_algorithm, &[name])?;

    // Encapsulation
    encaps(cli_conf_path, &ek_id, &encapsulation_file)?;
    assert!(encapsulation_file.exists());

    // Decapsulation
    decaps(
        cli_conf_path,
        &dk_id,
        &encapsulation_file,
        &session_key_file,
    )?;
    assert!(session_key_file.exists());

    let session_key = std::fs::read(&session_key_file)?;
    assert!(!session_key.is_empty());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_create_configurable_kem_key_pair() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    test_kem(&owner_client_conf_path, "ML-KEM512 KEM", "ml-kem-512")?;
    test_kem(&owner_client_conf_path, "ML-KEM768 KEM", "ml-kem-768")?;
    test_kem(&owner_client_conf_path, "P256 KEM", "p256")?;
    test_kem(&owner_client_conf_path, "CURVE25519 KEM", "curve25519")?;
    test_kem(
        &owner_client_conf_path,
        "ML-KEM512/P256 KEM",
        "ml-kem-512-p256",
    )?;
    test_kem(
        &owner_client_conf_path,
        "ML-KEM768/P256 KEM",
        "ml-kem-768-p256",
    )?;
    test_kem(
        &owner_client_conf_path,
        "ML-KEM512/CURVE25519 KEM",
        "ml-kem-512-curve25519",
    )?;
    test_kem(
        &owner_client_conf_path,
        "ML-KEM768/CURVE25519 KEM",
        "ml-kem-768-curve25519",
    )?;

    Ok(())
}

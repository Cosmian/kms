use std::{path::Path, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME, save_kms_cli_config,
        utils::{
            extract_uids::{extract_private_key, extract_public_key},
            recover_cmd_logs,
        },
    },
};

const SUB_COMMAND: &str = "pqc";

/// Create a PQC key pair and return the (`private_key_id`, `public_key_id`).
fn create_pqc_key_pair(
    cli_conf_path: &str,
    algorithm: &str,
    tags: &[&str],
) -> CosmianResult<(String, String)> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "create", "--algorithm", algorithm];
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg(SUB_COMMAND).args(args);

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

/// Encapsulate: writes encapsulation to `output_file`.
fn pqc_encapsulate(
    cli_conf_path: &str,
    public_key_id: &str,
    output_file: &Path,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let output_str = output_file.to_str().unwrap();
    let args = vec!["encrypt", "--key-id", public_key_id, "-o", output_str];
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Decapsulate: reads encapsulation from `input_file`, writes shared secret to `output_file`.
fn pqc_decapsulate(
    cli_conf_path: &str,
    private_key_id: &str,
    input_file: &Path,
    output_file: &Path,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let input_str = input_file.to_str().unwrap();
    let output_str = output_file.to_str().unwrap();
    let args = vec![
        "decrypt",
        "--key-id",
        private_key_id,
        input_str,
        "-o",
        output_str,
    ];
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Sign a file using an ML-DSA key.
fn pqc_sign(
    cli_conf_path: &str,
    input_file: &str,
    key_id: &str,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec!["sign", input_file, "--key-id", key_id, "-o", output_file];
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Verify an ML-DSA signature.
fn pqc_sign_verify(
    cli_conf_path: &str,
    data_file: &str,
    signature_file: &str,
    key_id: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec!["sign-verify", data_file, signature_file, "--key-id", key_id];
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout_str = std::str::from_utf8(&output.stdout)?;
        assert!(
            stdout_str.contains("Valid"),
            "Expected 'Valid' in output: {stdout_str}"
        );
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn test_kem(cli_conf_path: &str, name: &str, algorithm: &str) -> CosmianResult<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let encapsulation_file = tmp_path.join("encapsulation.enc");
    let session_key_file = tmp_path.join("session_key.plain");

    let (dk_id, ek_id) = create_pqc_key_pair(cli_conf_path, algorithm, &[name])?;

    pqc_encapsulate(cli_conf_path, &ek_id, &encapsulation_file)?;
    assert!(encapsulation_file.exists());

    pqc_decapsulate(
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

fn test_sign(cli_conf_path: &str, name: &str, algorithm: &str) -> CosmianResult<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let sig_file = tmp_path.join("signature.sig");

    let input_file = "../../../test_data/plain.txt";

    let (sk_id, pk_id) = create_pqc_key_pair(cli_conf_path, algorithm, &[name])?;

    pqc_sign(
        cli_conf_path,
        input_file,
        &sk_id,
        sig_file.to_str().unwrap(),
    )?;
    assert!(sig_file.exists());

    pqc_sign_verify(
        cli_conf_path,
        input_file,
        sig_file.to_str().unwrap(),
        &pk_id,
    )?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_ml_kem_ckms() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _) = save_kms_cli_config(ctx);

    test_kem(&owner_conf_path, "PQC ML-KEM-512", "ml-kem-512")?;
    test_kem(&owner_conf_path, "PQC ML-KEM-768", "ml-kem-768")?;
    test_kem(&owner_conf_path, "PQC ML-KEM-1024", "ml-kem-1024")?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_ml_dsa_ckms() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _) = save_kms_cli_config(ctx);

    test_sign(&owner_conf_path, "PQC ML-DSA-44", "ml-dsa-44")?;
    test_sign(&owner_conf_path, "PQC ML-DSA-65", "ml-dsa-65")?;
    test_sign(&owner_conf_path, "PQC ML-DSA-87", "ml-dsa-87")?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_hybrid_kem_ckms() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _) = save_kms_cli_config(ctx);

    test_kem(&owner_conf_path, "PQC X25519MLKEM768", "x25519-ml-kem-768")?;
    test_kem(&owner_conf_path, "PQC X448MLKEM1024", "x448-ml-kem-1024")?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_slh_dsa_ckms() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _) = save_kms_cli_config(ctx);

    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-128s",
        "slh-dsa-sha2-128s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-128f",
        "slh-dsa-sha2-128f",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-192s",
        "slh-dsa-sha2-192s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-192f",
        "slh-dsa-sha2-192f",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-256s",
        "slh-dsa-sha2-256s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHA2-256f",
        "slh-dsa-sha2-256f",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-128s",
        "slh-dsa-shake-128s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-128f",
        "slh-dsa-shake-128f",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-192s",
        "slh-dsa-shake-192s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-192f",
        "slh-dsa-shake-192f",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-256s",
        "slh-dsa-shake-256s",
    )?;
    test_sign(
        &owner_conf_path,
        "PQC SLH-DSA-SHAKE-256f",
        "slh-dsa-shake-256f",
    )?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_configurable_hybrid_kem_ckms() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_conf_path, _) = save_kms_cli_config(ctx);

    test_kem(&owner_conf_path, "PQC ML-KEM-512-P256", "ml-kem-512-p256")?;
    test_kem(&owner_conf_path, "PQC ML-KEM-768-P256", "ml-kem-768-p256")?;
    test_kem(
        &owner_conf_path,
        "PQC ML-KEM-512-Curve25519",
        "ml-kem-512-curve25519",
    )?;
    test_kem(
        &owner_conf_path,
        "PQC ML-KEM-768-Curve25519",
        "ml-kem-768-curve25519",
    )?;

    Ok(())
}

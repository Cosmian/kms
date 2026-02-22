use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND, elliptic_curve::create_key_pair::create_ec_key_pair,
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

/// Sign a file using EC keys via CLI
fn ec_sign(
    cli_conf_path: &str,
    input_file: &str,
    key_id: &str,
    output_file: Option<&str>,
    digested: bool,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["sign", input_file, "--key-id", key_id];
    if digested {
        args.push("--digested");
    }
    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        assert!(stdout.contains("Signature written to"));
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Verify a signature using EC keys via CLI
fn ec_sign_verify(
    cli_conf_path: &str,
    data_file: &str,
    signature_file: &str,
    key_id: &str,
    digested: bool,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["sign-verify", data_file, signature_file, "--key-id", key_id];
    if digested {
        args.push("--digested");
    }

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        assert!(stdout.contains("Signature verification is Valid"));
        return Ok(());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn ecdsa_digested_sign_verify_cli() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.ec.sig");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = openssl::sha::sha256(&data);
    std::fs::write(&digest_file, digest)?;

    let (private_key_id, public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

    // Sign digested input
    fs::remove_file(&sig_file).ok();
    ec_sign(
        &owner_client_conf_path,
        digest_file.to_str().unwrap(),
        &private_key_id,
        Some(sig_file.to_str().unwrap()),
        true,
    )?;
    assert!(sig_file.exists());

    // Verify digested input
    ec_sign_verify(
        &owner_client_conf_path,
        digest_file.to_str().unwrap(),
        sig_file.to_str().unwrap(),
        &public_key_id,
        true,
    )?;

    Ok(())
}

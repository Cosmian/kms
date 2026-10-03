use std::fs;

use cosmian_kms_cli_actions::actions::pgp::keys::create_key::{CreatePgpKeyAction, PgpAlgorithm};
use tempfile::NamedTempFile;
use test_kms_server::start_default_test_kms_server;

use super::{SUB_COMMAND, create_key::create_pgp_key};
use crate::{
    config::CKMS_CONF_ENV,
    error::result::CosmianResult,
    tests::utils::{ckms_bin, owner_config, recover_cmd_logs},
};

#[tokio::test]
async fn test_pgp_sign_verify_cli() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Sign Test <sign@example.com>".to_owned()),
        ..Default::default()
    };
    let uid = create_pgp_key(&cli_conf_path, &action)?;

    // Data file to sign
    let data_file = NamedTempFile::new()?;
    let data_path = data_file.path().to_str().unwrap();
    let original_bytes = b"Important document to sign with PGP key.";
    fs::write(data_path, original_bytes)?;

    // Signature output file
    let sig_file = NamedTempFile::new()?;
    let sig_path = sig_file.path().to_str().unwrap();

    let mut cmd_sign = ckms_bin();
    cmd_sign.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "sign",
        "-k",
        &uid,
        "-o",
        sig_path,
        data_path,
    ]);
    let out_sign = recover_cmd_logs(&mut cmd_sign);
    assert!(
        out_sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out_sign.stderr)
    );

    // Verify intact signature
    let mut cmd_verify = ckms_bin();
    cmd_verify.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "sign-verify",
        "-k",
        &uid,
        data_path,
        sig_path,
    ]);
    let out_verify = recover_cmd_logs(&mut cmd_verify);
    assert!(out_verify.status.success());
    let verify_stdout = String::from_utf8_lossy(&out_verify.stdout);
    assert!(
        verify_stdout.contains("Signature verification is Valid"),
        "expected 'Signature verification is Valid', got: {verify_stdout}"
    );

    // Tamper with data file by flipping one byte
    let mut tampered_bytes = original_bytes.to_vec();
    if let Some(b) = tampered_bytes.first_mut() {
        *b ^= 0xFF;
    }
    let tampered_file = NamedTempFile::new()?;
    let tampered_path = tampered_file.path().to_str().unwrap();
    fs::write(tampered_path, &tampered_bytes)?;

    let mut cmd_verify_tampered = ckms_bin();
    cmd_verify_tampered
        .env(CKMS_CONF_ENV, &cli_conf_path)
        .args([
            SUB_COMMAND,
            "sign-verify",
            "-k",
            &uid,
            tampered_path,
            sig_path,
        ]);
    let out_tampered = recover_cmd_logs(&mut cmd_verify_tampered);
    let tampered_stdout = String::from_utf8_lossy(&out_tampered.stdout);
    assert!(
        tampered_stdout.contains("Signature verification is Invalid"),
        "expected 'Signature verification is Invalid' for tampered data, got: {tampered_stdout}"
    );

    Ok(())
}

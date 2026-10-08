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
async fn test_pgp_encrypt_decrypt_cli() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Encrypt Test <enc@example.com>".to_owned()),
        ..Default::default()
    };
    let uid = create_pgp_key(&cli_conf_path, &action)?;

    // Plaintext file
    let plain_file = NamedTempFile::new()?;
    let plain_path = plain_file.path().to_str().unwrap();
    let original_data = b"Hello from ckms pgp encrypt/decrypt test!";
    fs::write(plain_path, original_data)?;

    // Encrypted output file
    let enc_file = NamedTempFile::new()?;
    let enc_path = enc_file.path().to_str().unwrap();

    let mut cmd_enc = ckms_bin();
    cmd_enc.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "encrypt",
        "-k",
        &uid,
        "-o",
        enc_path,
        plain_path,
    ]);
    let out_enc = recover_cmd_logs(&mut cmd_enc);
    assert!(
        out_enc.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&out_enc.stderr)
    );

    // Decrypted output file
    let dec_file = NamedTempFile::new()?;
    let dec_path = dec_file.path().to_str().unwrap();

    let mut cmd_dec = ckms_bin();
    cmd_dec.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "decrypt",
        "-k",
        &uid,
        "-o",
        dec_path,
        enc_path,
    ]);
    let out_dec = recover_cmd_logs(&mut cmd_dec);
    assert!(
        out_dec.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&out_dec.stderr)
    );

    let decrypted_data = fs::read(dec_path)?;
    assert_eq!(
        decrypted_data, original_data,
        "decrypted data must match original plaintext"
    );

    Ok(())
}

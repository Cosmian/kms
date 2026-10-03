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
async fn test_pgp_export_secret_and_public() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Export Test <export@example.com>".to_owned()),
        ..Default::default()
    };
    let uid = create_pgp_key(&cli_conf_path, &action)?;

    let secret_file = NamedTempFile::new()?;
    let secret_path = secret_file.path().to_str().unwrap();

    // Export secret key
    let mut cmd_sec = ckms_bin();
    cmd_sec.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &uid,
        "--key-format",
        "pgp-secret",
        secret_path,
    ]);
    let out_sec = recover_cmd_logs(&mut cmd_sec);
    assert!(
        out_sec.status.success(),
        "export secret failed: {}",
        String::from_utf8_lossy(&out_sec.stderr)
    );

    let secret_bytes = fs::read(secret_path)?;
    let secret_str = String::from_utf8(secret_bytes)?;
    assert!(
        secret_str.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "secret key did not start with expected header: {secret_str}"
    );

    // Export public key
    let public_file = NamedTempFile::new()?;
    let public_path = public_file.path().to_str().unwrap();

    let mut cmd_pub = ckms_bin();
    cmd_pub.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &uid,
        "--key-format",
        "pgp-public",
        public_path,
    ]);
    let out_pub = recover_cmd_logs(&mut cmd_pub);
    assert!(
        out_pub.status.success(),
        "export public failed: {}",
        String::from_utf8_lossy(&out_pub.stderr)
    );

    let public_bytes = fs::read(public_path)?;
    let public_str = String::from_utf8(public_bytes)?;
    assert!(
        public_str.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "public key did not start with expected header: {public_str}"
    );

    Ok(())
}

#[tokio::test]
async fn test_pgp_import_roundtrip() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Import Roundtrip <import@example.com>".to_owned()),
        ..Default::default()
    };
    let orig_uid = create_pgp_key(&cli_conf_path, &action)?;

    // Export public key
    let pub_file1 = NamedTempFile::new()?;
    let pub_path1 = pub_file1.path().to_str().unwrap();

    let mut cmd_exp1 = ckms_bin();
    cmd_exp1.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &orig_uid,
        "--key-format",
        "pgp-public",
        pub_path1,
    ]);
    let out_exp1 = recover_cmd_logs(&mut cmd_exp1);
    assert!(out_exp1.status.success());

    let pub_bytes1 = fs::read(pub_path1)?;

    // Import under a new id
    let new_uid = format!("pgp-imported-{}", uuid::Uuid::new_v4());
    let mut cmd_imp = ckms_bin();
    cmd_imp.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "import",
        "--key-format",
        "pgp",
        pub_path1,
        &new_uid,
    ]);
    let out_imp = recover_cmd_logs(&mut cmd_imp);
    assert!(
        out_imp.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out_imp.stderr)
    );

    // Re-export public key from new UID
    let pub_file2 = NamedTempFile::new()?;
    let pub_path2 = pub_file2.path().to_str().unwrap();

    let mut cmd_exp2 = ckms_bin();
    cmd_exp2.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &new_uid,
        "--key-format",
        "pgp-public",
        pub_path2,
    ]);
    let out_exp2 = recover_cmd_logs(&mut cmd_exp2);
    assert!(out_exp2.status.success());

    let pub_bytes2 = fs::read(pub_path2)?;
    assert_eq!(
        pub_bytes1, pub_bytes2,
        "exported public keys before and after import roundtrip must match"
    );

    Ok(())
}

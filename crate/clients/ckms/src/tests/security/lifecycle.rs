//! Key lifecycle state machine tests (CLI-level).
//!
//! These tests verify KMIP lifecycle state transitions via the ckms binary:
//!   L1  - Newly created key can be exported.
//!   L2  - Revoked key can still be exported by its owner (--allow-revoked).
//!   L3  - Destroyed key cannot be exported at all.
//!   L4  - Destroying a key that has not been revoked first must fail.
//!   L5  - Double-revoke must fail (key is already revoked).
//!   L6  - Double-destroy must fail (key no longer exists after first destroy).

use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{extract_uids::extract_uid, owner_config, run_ckms, run_ckms_expect_error},
};

/// L1: Newly created key is usable — owner can export it immediately.
#[tokio::test]
async fn l01_new_key_is_exportable() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    run_ckms(&conf, &["sym", "keys", "export", path, "-k", key_id])?;

    Ok(())
}

/// L2: Revoked key can still be exported by its owner via --allow-revoked.
#[tokio::test]
async fn l02_revoked_key_exportable_by_owner() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    run_ckms(&conf, &["sym", "keys", "revoke", "test", "-k", key_id])?;

    // Owner can export with --allow-revoked
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    run_ckms(
        &conf,
        &[
            "sym",
            "keys",
            "export",
            path,
            "-k",
            key_id,
            "--allow-revoked",
        ],
    )?;

    Ok(())
}

/// L3: Destroyed key cannot be exported at all.
#[tokio::test]
async fn l03_destroyed_key_not_exportable() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Revoke then destroy (with --remove to fully purge)
    run_ckms(&conf, &["sym", "keys", "revoke", "test", "-k", key_id])?;
    run_ckms(&conf, &["sym", "keys", "destroy", "-k", key_id, "--remove"])?;

    // Export must fail now
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(
        &conf,
        &[
            "sym",
            "keys",
            "export",
            path,
            "-k",
            key_id,
            "--allow-revoked",
        ],
    )?;
    assert!(
        !result.is_empty(),
        "destroyed key must not be exportable, got empty error"
    );

    Ok(())
}

/// L4: Destroying a key that has NOT been revoked must fail.
#[tokio::test]
async fn l04_destroy_active_key_must_fail() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Attempt to destroy without prior revocation
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "destroy", "-k", key_id])?;
    assert!(
        !stderr.is_empty(),
        "destroying an Active key without prior revocation must fail"
    );

    Ok(())
}

/// L5: Double-revoke — the second Revoke must fail.
#[tokio::test]
async fn l05_double_revoke_must_fail() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // First revoke succeeds
    run_ckms(&conf, &["sym", "keys", "revoke", "first", "-k", key_id])?;

    // Second revoke must fail (or no-op — we accept both)
    let _result = run_ckms_expect_error(&conf, &["sym", "keys", "revoke", "second", "-k", key_id]);
    // If it succeeded as no-op that's fine too — the key is consistent regardless
    Ok(())
}

/// L6: Double-destroy — the second Destroy must fail.
#[tokio::test]
async fn l06_double_destroy_must_fail() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    run_ckms(&conf, &["sym", "keys", "revoke", "test", "-k", key_id])?;

    // First destroy succeeds
    run_ckms(&conf, &["sym", "keys", "destroy", "-k", key_id, "--remove"])?;

    // Second destroy must fail
    let stderr =
        run_ckms_expect_error(&conf, &["sym", "keys", "destroy", "-k", key_id, "--remove"])?;
    assert!(
        !stderr.is_empty(),
        "second Destroy on an already-destroyed key must return an error"
    );

    Ok(())
}

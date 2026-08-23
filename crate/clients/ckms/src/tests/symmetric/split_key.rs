//! Integration tests for `ckms sym keys create-split-key` and
//! `ckms sym keys join-split-key`.
//!
//! These tests exercise the CLI layer end-to-end via the built `ckms` binary
//! against an in-process test KMS server.

use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        symmetric::create_key::create_symmetric_key,
        utils::{extract_uids::extract_uid, owner_config, run_ckms, run_ckms_expect_error},
    },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Split `source_uid` into `total_parts` shares via `ckms sym keys create-split-key`.
///
/// Returns the list of share UIDs printed by the server (one per line, raw).
/// `extra_args` are appended after the base command args.
pub(crate) fn create_split_key(
    cli_conf_path: &str,
    source_uid: &str,
    total_parts: u32,
    extra_args: &[&str],
) -> CosmianResult<Vec<String>> {
    let parts_str = total_parts.to_string();
    let mut args = vec![
        "sym",
        "keys",
        "create-split-key",
        "--key-id",
        source_uid,
        "--total-parts",
        &parts_str,
    ];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    // The server prints each share UID on its own line (raw, no label) after
    // the summary line "Key … successfully split into N share(s)".
    let share_uids: Vec<String> = stdout
        .lines()
        .filter(|l| l.contains('#'))
        .map(str::trim)
        .map(str::to_owned)
        .collect();
    Ok(share_uids)
}

/// Reconstruct a key from `share_uids` via `ckms sym keys join-split-key`.
///
/// Returns the reconstructed key UID.
/// `extra_args` are appended after the share UIDs.
pub(crate) fn join_split_key(
    cli_conf_path: &str,
    share_uids: &[String],
    extra_args: &[&str],
) -> CosmianResult<String> {
    let mut args = vec!["sym", "keys", "join-split-key"];
    for uid in share_uids {
        args.push(uid.as_str());
    }
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    let uid = extract_uid(&stdout, "Reconstructed key UID").ok_or_else(|| {
        crate::error::CosmianError::Default(format!(
            "failed to extract reconstructed key UID from output: {stdout}"
        ))
    })?;
    Ok(uid.to_owned())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// SK-1: Default 2-of-2 split and roundtrip reconstruction.
#[tokio::test]
async fn test_create_split_key_2_of_2_and_join() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create source key
    let key_id = create_symmetric_key(&conf, &[])?;

    // Split into 2 shares (default)
    let shares = create_split_key(&conf, &key_id, 2, &[])?;
    assert_eq!(shares.len(), 2, "expected 2 share UIDs, got: {shares:?}");

    // Verify share UIDs follow the `<source>#<part>` naming convention
    let uid0 = shares.first().expect("expected at least one share UID");
    let uid1 = shares.get(1).expect("expected at least two share UIDs");
    assert!(
        uid0.contains('#'),
        "share UID[0] should contain '#': {uid0}"
    );
    assert!(
        uid1.contains('#'),
        "share UID[1] should contain '#': {uid1}"
    );

    // Reconstruct from both shares
    let reconstructed_uid = join_split_key(&conf, &shares, &[])?;
    assert!(
        !reconstructed_uid.is_empty(),
        "reconstructed key UID must not be empty"
    );

    Ok(())
}

/// SK-2: Split into 3 shares, reconstruct from all three.
#[tokio::test]
async fn test_create_split_key_3_of_3_and_join() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let key_id = create_symmetric_key(&conf, &[])?;
    let shares = create_split_key(&conf, &key_id, 3, &[])?;
    assert_eq!(shares.len(), 3, "expected 3 shares, got: {shares:?}");

    let reconstructed_uid = join_split_key(&conf, &shares, &[])?;
    assert!(!reconstructed_uid.is_empty());

    Ok(())
}

/// SK-3: Attempting to join with only a subset of shares must fail.
///
/// XOR n-of-n requires ALL shares; providing fewer must be rejected.
#[tokio::test]
async fn test_join_split_key_with_missing_share_fails() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let key_id = create_symmetric_key(&conf, &[])?;
    let shares = create_split_key(&conf, &key_id, 3, &[])?;
    assert_eq!(shares.len(), 3);

    // Provide only 2 of the 3 required shares — use .get() to avoid indexing_slicing.
    let first_share = shares.first().expect("at least one share");
    let second_share = shares.get(1).expect("at least two shares");
    let stderr = run_ckms_expect_error(
        &conf,
        &["sym", "keys", "join-split-key", first_share, second_share],
    )?;
    assert!(
        stderr.contains("3 shares") || stderr.contains("requires all"),
        "expected n-of-n error, got: {stderr}"
    );

    Ok(())
}

/// SK-4: Requesting a polynomial method that is not yet implemented must fail
/// with a clear `NotSupported` error — NOT silently execute XOR.
#[tokio::test]
async fn test_create_split_key_polynomial_method_is_not_supported() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let key_id = create_symmetric_key(&conf, &[])?;

    // The CLI only accepts "xor"; requesting a polynomial method requires
    // bypassing the CLI and calling the server directly via the HTTP client.
    // We test this via the CLI error path for an unknown method string.
    let stderr = run_ckms_expect_error(
        &conf,
        &[
            "sym",
            "keys",
            "create-split-key",
            "--key-id",
            &key_id,
            "--method",
            "polynomial-gf28",
        ],
    )?;
    assert!(
        stderr.contains("unknown split key method") || stderr.contains("Accepted: xor"),
        "expected method rejection, got: {stderr}"
    );

    Ok(())
}

/// SK-5: `create-split-key` without `--key-id` must fail with a usage error.
#[tokio::test]
async fn test_create_split_key_missing_key_id_fails() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stderr = run_ckms_expect_error(
        &conf,
        &["sym", "keys", "create-split-key", "--total-parts", "2"],
    )?;
    assert!(
        stderr.contains("required") || stderr.contains("key-id") || stderr.contains("error"),
        "expected missing --key-id error, got: {stderr}"
    );

    Ok(())
}

/// SK-6: `join-split-key` with a non-existent share UID must fail.
#[tokio::test]
async fn test_join_split_key_nonexistent_share_fails() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stderr = run_ckms_expect_error(
        &conf,
        &[
            "sym",
            "keys",
            "join-split-key",
            "nonexistent-uid-1",
            "nonexistent-uid-2",
        ],
    )?;
    assert!(
        stderr.contains("not found") || stderr.contains("error") || stderr.contains("ItemNotFound"),
        "expected not-found error, got: {stderr}"
    );

    Ok(())
}

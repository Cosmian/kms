//! Cross-user access control tests (CLI-level).
//!
//! Uses a TLS cert-auth test server with two distinct user identities:
//!   - owner: `owner.client@acme.com`
//!   - user:  `user.client@acme.com`
//!
//! These tests verify that:
//!   P1  - A user cannot export a key they do not own.
//!   P2  - A user cannot revoke a key they do not own.
//!   P3  - A user cannot destroy a key they do not own.
//!   P4  - After the owner grants `get`, the user can export the key.
//!   P5  - After the owner revokes the grant, the user can no longer export.
//!   P6  - A user cannot grant access to a key they do not own.

use serial_test::serial;
use test_kms_server::start_default_test_kms_server_with_cert_auth;

use crate::{
    error::result::CosmianResult,
    tests::utils::{
        extract_uids::extract_uid, load_client_config, run_ckms, run_ckms_expect_error,
    },
};

const USER_ID: &str = "user.client@acme.com";

// ---------------------------------------------------------------------------
// P1: User cannot export an owner-only key (no grant)
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p01_user_cannot_export_ungranted_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    // Owner creates a key
    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // User tries to export → must fail
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "export", path, "-k", key_id]);
    assert!(
        result.is_ok(),
        "user must not export an owner key without a grant"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// P2: User cannot revoke a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p02_user_cannot_revoke_unowned_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    let result = run_ckms_expect_error(
        &user_conf,
        &["sym", "keys", "revoke", "hijack attempt", "-k", key_id],
    );
    assert!(result.is_ok(), "user must not revoke a key they do not own");

    Ok(())
}

// ---------------------------------------------------------------------------
// P3: User cannot destroy a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p03_user_cannot_destroy_unowned_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Owner revokes first so destroy is allowed in the lifecycle
    run_ckms(
        &owner_conf,
        &["sym", "keys", "revoke", "setup", "-k", key_id],
    )?;

    // User tries to destroy → must fail
    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "destroy", "-k", key_id]);
    assert!(
        result.is_ok(),
        "user must not destroy a key they do not own"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// P4: Owner grants `get` → user can export the key
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p04_grant_allows_user_export() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Owner grants `get` to user
    run_ckms(
        &owner_conf,
        &["access-rights", "grant", USER_ID, "get", "-i", key_id],
    )?;

    // User can now export
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    run_ckms(&user_conf, &["sym", "keys", "export", path, "-k", key_id])?;

    Ok(())
}

// ---------------------------------------------------------------------------
// P5: Owner revokes grant → user can no longer export the key
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p05_revoke_grant_removes_access() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Grant
    run_ckms(
        &owner_conf,
        &["access-rights", "grant", USER_ID, "get", "-i", key_id],
    )?;

    // Confirm user can export
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    run_ckms(&user_conf, &["sym", "keys", "export", path, "-k", key_id])?;

    // Revoke
    run_ckms(
        &owner_conf,
        &["access-rights", "revoke", USER_ID, "get", "-i", key_id],
    )?;

    // User should no longer have access
    let tmp2 = tempfile::NamedTempFile::new()?;
    let path2 = tmp2.path().to_str().unwrap();
    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "export", path2, "-k", key_id]);
    assert!(
        result.is_ok(),
        "user must not export key after grant was revoked"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// P6: User cannot grant their own access to a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
async fn p06_user_cannot_self_grant() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner_conf = load_client_config("cert_auth_owner.toml", ctx);
    let user_conf = load_client_config("cert_auth_user.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // User tries to grant themselves access → must fail
    let result = run_ckms_expect_error(
        &user_conf,
        &["access-rights", "grant", USER_ID, "get", "-i", key_id],
    );
    assert!(
        result.is_ok(),
        "user must not be able to self-grant access on a key they do not own"
    );

    Ok(())
}

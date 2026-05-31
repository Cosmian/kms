//! Privileged-user bypass tests (CLI-level).
//!
//! Verifies that the `privileged_users` server configuration correctly scopes
//! privileges: only listed users can create keys; the privilege does NOT bleed
//! into read or access-management operations on keys owned by other users.
//!
//!   PB1 - Privileged user can create a symmetric key
//!   PB2 - Non-privileged user cannot create a key
//!   PB3 - Owner grants/revokes Export → works correctly for user
//!   PB4 - Privilege for Create does not grant implicit read access

use test_kms_server::start_default_test_kms_server_with_privileged_users;

use crate::{
    error::result::CosmianResult,
    tests::utils::{
        extract_uids::extract_uid, load_client_config, run_ckms, run_ckms_expect_error,
    },
};

const OWNER_IDENTITY: &str = "owner.client@acme.com";
const USER_IDENTITY: &str = "user.client@acme.com";

// ---------------------------------------------------------------------------
// PB1: Privileged user can create a symmetric key.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb01_privileged_user_can_create_key() -> CosmianResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let owner_conf = load_client_config("privileged_users_owner.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    assert!(
        stdout.contains("Unique identifier"),
        "Privileged user must be able to create a key, got: {stdout}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// PB2: Non-privileged user cannot create a key when privileged_users is set.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb02_non_privileged_user_cannot_create() -> CosmianResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let user_conf = load_client_config("privileged_users_user.toml", ctx);

    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "create"]);
    assert!(
        result.is_ok(),
        "Non-privileged user must not be able to create keys"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// PB3: Owner grants Export to user, then revokes → user loses access.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb03_revoke_grant_denies_subsequent_access() -> CosmianResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let owner_conf = load_client_config("privileged_users_owner.toml", ctx);
    let user_conf = load_client_config("privileged_users_user.toml", ctx);

    // Owner creates a key
    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Owner grants Export to user
    run_ckms(
        &owner_conf,
        &["access-rights", "grant", USER_IDENTITY, "get", "-i", key_id],
    )?;

    // Revoke the grant
    run_ckms(
        &owner_conf,
        &[
            "access-rights",
            "revoke",
            USER_IDENTITY,
            "get",
            "-i",
            key_id,
        ],
    )?;

    // User export must fail
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "export", path, "-k", key_id]);
    assert!(
        result.is_ok(),
        "Export must fail after grant has been revoked"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// PB4: Privilege for Create does not grant implicit read access to keys
//      created by other users.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb04_privilege_does_not_bleed_into_read() -> CosmianResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let owner_conf = load_client_config("privileged_users_owner.toml", ctx);
    let user_conf = load_client_config("privileged_users_user.toml", ctx);

    // Owner creates a key
    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // User tries to export without any grant → must fail
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(&user_conf, &["sym", "keys", "export", path, "-k", key_id]);
    assert!(
        result.is_ok(),
        "Non-privileged user must not read a key they do not own without a grant"
    );

    Ok(())
}

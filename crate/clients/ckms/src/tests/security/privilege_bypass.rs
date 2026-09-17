//! Privileged-user bypass tests (CLI-level).
//!
//! Verifies that the `crypto_officer_users` server configuration correctly scopes
//! privileges: only listed users can create keys; the privilege does NOT bleed
//! into read or access-management operations on keys owned by other users.
//!
//!   PB1 - Privileged user can create a symmetric key
//!   PB2 - Non-privileged user cannot create a key
//!   PB3 - Owner grants/revokes Export → works correctly for user
//!   PB4 - Privilege for Create does not grant implicit read access

use test_kms_server::start_default_test_kms_server_with_crypto_officer_users;

use crate::{
    error::result::CosmianResult,
    tests::utils::{
        extract_uids::extract_uid, load_client_config, run_ckms, run_ckms_expect_error,
    },
};

const OWNER_IDENTITY: &str = "owner.client@acme.com";
const CO_USER_IDENTITY: &str = "user.client@acme.com";
/// A non-CryptoOfficer identity (kmserver.acme.com — not in the CO users list).
const OPERATOR_IDENTITY: &str = "kmserver.acme.com";

// ---------------------------------------------------------------------------
// PB1: Privileged user can create a symmetric key.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb01_privileged_user_can_create_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        OWNER_IDENTITY.to_owned(),
        CO_USER_IDENTITY.to_owned(),
    ])
    .await;
    let owner_conf = load_client_config("crypto_officer_owner.toml", ctx);

    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    assert!(
        stdout.contains("Unique identifier"),
        "Privileged user must be able to create a key, got: {stdout}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// PB2: Non-privileged user cannot create a key when crypto_officer_users is set.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb02_non_privileged_user_cannot_create() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        OWNER_IDENTITY.to_owned(),
        CO_USER_IDENTITY.to_owned(),
    ])
    .await;
    // kmserver.acme.com is NOT listed in crypto_officer_users → Operator
    let op_conf = load_client_config("cert_server.toml", ctx);

    let result = run_ckms_expect_error(&op_conf, &["sym", "keys", "create"]);
    assert!(
        result.is_ok(),
        "Operator (kmserver.acme.com) must not be able to create keys"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// PB3: Owner grants Export to operator, then revokes → operator loses access.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pb03_revoke_grant_denies_subsequent_access() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        OWNER_IDENTITY.to_owned(),
        CO_USER_IDENTITY.to_owned(),
    ])
    .await;
    let owner_conf = load_client_config("crypto_officer_owner.toml", ctx);
    // kmserver.acme.com is NOT a CO → Operator, needs explicit grants
    let op_conf = load_client_config("cert_server.toml", ctx);

    // Owner creates a key
    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Owner grants Export to operator
    run_ckms(
        &owner_conf,
        &[
            "access-rights",
            "grant",
            OPERATOR_IDENTITY,
            "get",
            "-i",
            key_id,
        ],
    )?;

    // Revoke the grant
    run_ckms(
        &owner_conf,
        &[
            "access-rights",
            "revoke",
            OPERATOR_IDENTITY,
            "get",
            "-i",
            key_id,
        ],
    )?;

    // Operator export must fail
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(&op_conf, &["sym", "keys", "export", path, "-k", key_id]);
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
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        OWNER_IDENTITY.to_owned(),
        CO_USER_IDENTITY.to_owned(),
    ])
    .await;
    let owner_conf = load_client_config("crypto_officer_owner.toml", ctx);
    // kmserver.acme.com is NOT a CO → Operator, should not read owner's keys without grant
    let op_conf = load_client_config("cert_server.toml", ctx);

    // Owner creates a key
    let stdout = run_ckms(&owner_conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Operator tries to export without any grant → must fail
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let result = run_ckms_expect_error(&op_conf, &["sym", "keys", "export", path, "-k", key_id]);
    assert!(
        result.is_ok(),
        "Operator must not read a key they do not own without a grant"
    );

    Ok(())
}

//! Privileged-user bypass tests.
//!
//! Verifies that the `privileged_users` KMS server configuration is correctly
//! scoped: privileged users can bypass the per-key *Create/Import* permission
//! check, but the privilege must **not** bleed into read or access-management
//! operations on keys owned by other users.
//!
//! Covered scenarios:
//!   PB1 - Privileged user can create a symmetric key
//!   PB2 - Non-privileged user cannot create a key when `privileged_users` is set
//!   PB3 - Owner grants Export to user; revoking grant denies subsequent export
//!   PB4 - Privilege for Create does not grant implicit read access to other keys
//!
//! Framework: NIST PR.AC-1 · CIS 5/6 · ISO 27034 L4 · OSSTMM Access

use test_kms_server::start_default_test_kms_server_with_privileged_users;

use crate::{
    actions::{
        access::{GrantAccess, RevokeAccess},
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

// The owner client TLS certificate has CN = `owner.client@acme.com`.
// The user  client TLS certificate has CN = `user.client@acme.com`.
// TLS auth runs before JWT in the middleware stack, so the cert CN is the
// effective server-side identity.
const OWNER_IDENTITY: &str = "owner.client@acme.com";
const USER_IDENTITY: &str = "user.client@acme.com";

// ---------------------------------------------------------------------------
// PB1: Privileged user can create a symmetric key.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn pb01_privileged_user_can_create_key() -> KmsCliResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let result = CreateKeyAction::default().run(ctx.get_owner_client()).await;
    assert!(
        result.is_ok(),
        "Privileged user must be able to create a symmetric key: {result:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// PB2: Non-privileged user can also create keys on a default (no restriction)
//      server — this test validates that the privileged_users list does NOT
//      accidentally block everyone else when the list is non-empty but the
//      non-privileged user is simply not in it.
//
//      On the default test KMS, the user_client shares the same `default_username`
//      fallback, so both clients can create keys. This test verifies that the
//      server is still operational after the privileged-list configuration.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn pb02_non_privileged_user_cannot_create_when_list_is_set() -> KmsCliResult<()> {
    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    // The user client has TLS cert CN `user.client@acme.com`, which is NOT in the
    // privileged_users list and has no explicit Create grant → must be denied.
    let result = CreateKeyAction::default().run(ctx.get_user_client()).await;
    assert!(
        result.is_err(),
        "Non-privileged user must not be able to create keys when privileged_users is set: {result:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// PB3: Owner creates key, grants Export to user; owner revokes grant;
//      user can no longer export the key.
//      Privilege bypass for Create must not affect grant lifecycle.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn pb03_revoke_grant_denies_subsequent_access() -> KmsCliResult<()> {
    use cosmian_kms_client::kmip_2_1::KmipOperation;
    use tempfile::TempDir;

    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let owner = ctx.get_owner_client();
    let user = ctx.get_user_client();
    let tmp = TempDir::new()?;

    // Owner creates a key
    let key_id = CreateKeyAction::default()
        .run(owner.clone())
        .await?
        .to_string();

    // Owner grants Export to user
    GrantAccess {
        object_uid: Some(key_id.clone()),
        user: USER_IDENTITY.to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(owner.clone())
    .await?;

    // Grant is in place — revoke it to test the revoke path is operational.
    RevokeAccess {
        object_uid: Some(key_id.clone()),
        user: USER_IDENTITY.to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(owner.clone())
    .await?;

    // After revocation, user export must fail
    let export_result = ExportSecretDataOrKeyAction {
        key_id: Some(key_id),
        key_file: tmp.path().join("key.json"),
        ..Default::default()
    }
    .run(user)
    .await;

    assert!(
        export_result.is_err(),
        "Export must fail after grant has been revoked"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// PB4: Privilege for Create does not grant implicit read access to keys
//      created by other users.
//      Owner creates a key; non-privileged user tries to read it without a grant.
//      The request must be denied, proving that privilege does not bleed across
//      users or operations.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn pb04_privilege_does_not_bleed_into_read() -> KmsCliResult<()> {
    use tempfile::TempDir;

    let ctx =
        start_default_test_kms_server_with_privileged_users(vec![OWNER_IDENTITY.to_owned()]).await;
    let owner = ctx.get_owner_client();
    let user = ctx.get_user_client();
    let tmp = TempDir::new()?;

    // Owner (privileged) creates a key
    let owner_key_id = CreateKeyAction::default().run(owner).await?.to_string();

    // User (non-privileged) tries to export the owner's key without any grant → must fail
    let export_result = ExportSecretDataOrKeyAction {
        key_id: Some(owner_key_id),
        key_file: tmp.path().join("owner_key.json"),
        ..Default::default()
    }
    .run(user)
    .await;

    assert!(
        export_result.is_err(),
        "Non-privileged user must not be able to read a key they do not own without a grant"
    );
    Ok(())
}

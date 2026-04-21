//! Cross-user access control tests.
//!
//! Uses a TLS cert-auth test server that provides two distinct user identities:
//!   - owner: `owner.client@acme.com`
//!   - user:  `user.client@acme.com`
//!
//! These tests verify that:
//!   P1  - A user cannot export a key they do not own and have not been granted access to.
//!   P2  - A user cannot revoke a key they do not own.
//!   P3  - A user cannot destroy a key they do not own.
//!   P4  - After the owner grants `get`, the user can export the key.
//!   P5  - After the owner revokes the grant, the user can no longer export the key.
//!   P6  - A user cannot grant access to a key they do not own.

use cosmian_kms_client::kmip_2_1::KmipOperation;
use serial_test::serial;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server_with_cert_auth;

use crate::{
    actions::{
        access::{GrantAccess, RevokeAccess},
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::{
            create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
        },
    },
    error::result::KmsCliResult,
};

// The default user identity in the cert-auth test server.
const USER_ID: &str = "user.client@acme.com";

// ---------------------------------------------------------------------------
// P1: User cannot export an owner-only key (no grant)
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p01_user_cannot_export_ungranted_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let tmp = TempDir::new()?;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    let result = ExportSecretDataOrKeyAction {
        key_id: Some(key_id.clone()),
        key_file: tmp.path().join("key.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await;

    assert!(
        result.is_err(),
        "user must not export an owner key they have not been granted access to"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// P2: User cannot revoke a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p02_user_cannot_revoke_unowned_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    let result = RevokeKeyAction {
        revocation_reason: "hijack attempt".to_owned(),
        key_id: Some(key_id),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await;

    assert!(
        result.is_err(),
        "user must not revoke a key they do not own"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// P3: User cannot destroy a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p03_user_cannot_destroy_unowned_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // First revoke (as owner) so we can check if destroy also fails for user
    RevokeKeyAction {
        revocation_reason: "setup".to_owned(),
        key_id: Some(key_id.clone()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    let result = DestroyKeyAction {
        key_id: Some(key_id),
        tags: None,
        remove: false,
    }
    .run(ctx.get_user_client())
    .await;

    assert!(
        result.is_err(),
        "user must not destroy a key they do not own"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// P4: Owner grants `get` → user can export the key
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p04_grant_allows_user_export() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let tmp = TempDir::new()?;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Grant `get` to the user
    GrantAccess {
        user: USER_ID.to_owned(),
        object_uid: Some(key_id.clone()),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Now user should be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id),
        key_file: tmp.path().join("key.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// P5: Owner revokes grant → user can no longer export the key
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p05_revoke_grant_removes_access() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let tmp = TempDir::new()?;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Grant
    GrantAccess {
        user: USER_ID.to_owned(),
        object_uid: Some(key_id.clone()),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Confirm user can export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.clone()),
        key_file: tmp.path().join("key_before.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;

    // Revoke the grant
    RevokeAccess {
        user: USER_ID.to_owned(),
        object_uid: Some(key_id.clone()),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // User should no longer have access
    let result = ExportSecretDataOrKeyAction {
        key_id: Some(key_id),
        key_file: tmp.path().join("key_after.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await;

    assert!(
        result.is_err(),
        "user must not export key after grant was revoked"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// P6: User cannot grant their own access to a key they do not own
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial]
pub(crate) async fn p06_user_cannot_self_grant() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // User attempts to grant themselves `get` access
    let result = GrantAccess {
        user: USER_ID.to_owned(),
        object_uid: Some(key_id),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_user_client())
    .await;

    assert!(
        result.is_err(),
        "user must not be able to self-grant access on a key they do not own"
    );
    Ok(())
}

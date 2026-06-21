//! Authorization and permission checks for KMIP operations.
//!
//! Contains standalone guards for operation-level authorization,
//! `Create` permission, and `ProtectionStorageMasks` rejection.

use cosmian_kms_server_database::{Database, reexport::cosmian_kmip::kmip_2_1::KmipOperation};

use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission, uid_utils::has_prefix},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Enforce that the caller has `Create` access-right.
///
/// When `privileged_users` is configured, the user must either:
/// - have been explicitly granted the `Create` operation on any object,
/// - be listed in `privileged_users`, or
/// - be the `default_username` (unauthenticated / local access).
///
/// This check applies uniformly to `Create`, `CreateKeyPair`, `Import`, and `Register`.
pub(crate) async fn enforce_create_permission(kms: &KMS, user: &str) -> KResult<()> {
    if let Some(ref users) = kms.params.privileged_users {
        if user == kms.params.default_username
            || users.iter().any(|u| u == user)
            || user_has_permission(user, None, &KmipOperation::Create, kms).await?
        {
            return Ok(());
        }
        kms_bail!(KmsError::Unauthorized(
            "User does not have create access-right.".to_owned()
        ))
    }
    // If no privileged user was set, all users have the `Create` right.
    Ok(())
}

/// Reject requests that specify `ProtectionStorageMasks`.
///
/// KMIP defines this field but the server does not implement storage-level
/// masking.  Fail early rather than silently ignoring the field.
#[allow(clippy::missing_const_for_fn)] // kms_bail! is not const-compatible
pub(crate) fn reject_protection_storage_masks(has_masks: bool) -> KResult<()> {
    if has_masks {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }
    Ok(())
}

// ─── Operation-level authorization ───────────────────────────────────────────

/// Check whether a user is authorized to perform `operation` on the object
/// identified by `uid`.
///
/// The user is authorized if they own the object, or have been granted the
/// specific `operation` **or** `Get` (which implies read-level access).
/// For HSM keys (prefix-based UIDs), the `Get` wildcard is **not** applied.
pub(super) async fn is_user_authorized(
    db: &Database,
    uid: &str,
    user: &str,
    operation: KmipOperation,
) -> KResult<bool> {
    if db.is_object_owned_by(uid, user).await? {
        return Ok(true);
    }
    let ops = db.list_user_operations_on_object(uid, user, false).await?;

    // HSM keys: each operation must be explicitly granted — no Get wildcard
    if has_prefix(uid).is_some() {
        return Ok(ops.iter().any(|p| *p == operation));
    }

    Ok(ops
        .iter()
        .any(|p| *p == operation || *p == KmipOperation::Get))
}

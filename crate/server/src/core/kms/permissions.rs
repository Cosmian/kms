use std::collections::{BTreeSet, HashSet};

use actix_web::{HttpMessage, HttpRequest};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier},
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use crate::{
    core::{
        KMS,
        retrieve_object_utils::user_has_permission,
        uid_utils::{ObjectHandle, from_request},
    },
    error::KmsError,
    kms_bail,
    middlewares::{AuthenticatedUser, UserId},
    result::{KResult, KResultHelper},
};

impl KMS {
    /// Grant access to a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn grant_access(&self, access: &Access, owner: &UserId) -> KResult<()> {
        // if create access right is set, grant access to Create for the * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            let co_users = &self.params.crypto_officer.users;
            if !co_users.is_empty() {
                if !co_users.iter().any(|u| u.as_str() == owner.as_str()) {
                    kms_bail!(KmsError::Unauthorized(
                        "Only Crypto Officer users can grant/revoke create access right to a \
                         user."
                            .to_owned()
                    ))
                }
                let user_id = &access.user_id;
                if co_users.contains(user_id) {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "User `{user_id}` is a Crypto Officer — create access right can't be \
                         granted or revoked on their behalf."
                    )))
                }
                let user_id_typed =
                    UserId::try_new(user_id.as_str()).map_err(KmsError::InvalidRequest)?;
                self.database
                    .grant_operations("*", &user_id_typed, HashSet::from([KmipOperation::Create]))
                    .await?;

                // Record metrics for Create permission grant
                if let Some(ref metrics) = self.metrics {
                    metrics.record_permission_grant(user_id.as_str(), "Create");
                }
            }
        }

        if !updated_operations_types.is_empty() {
            let handle = from_request(access.unique_identifier.as_ref(), "GrantAccess")?;
            let uid = handle.as_str();

            // check the object identified by its `uid` is really owned by `owner`
            if !self.database.is_object_owned_by(uid, owner).await? {
                kms_bail!(KmsError::Unauthorized(format!(
                    "Object with uid `{uid}` is not owned by owner `{owner}`"
                )))
            }

            // check if an owner is trying to grant themselves
            if *owner == access.user_id {
                kms_bail!(KmsError::Unauthorized(
                    "You can't grant yourself, you have already all rights on your own objects"
                        .to_owned()
                ))
            }

            // HSM keys: block granting Destroy and Revoke — these are admin-only operations
            if handle.is_hsm() {
                let forbidden: Vec<&KmipOperation> = updated_operations_types
                    .iter()
                    .filter(|op| matches!(op, KmipOperation::Destroy | KmipOperation::Revoke))
                    .collect();
                if !forbidden.is_empty() {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "Cannot grant {forbidden:?} on HSM key `{uid}`: these operations are \
                         reserved for HSM admins only"
                    )))
                }
            }

            let grant_user_id =
                UserId::try_new(access.user_id.as_str()).map_err(KmsError::InvalidRequest)?;
            self.database
                .grant_operations(
                    uid,
                    &grant_user_id,
                    HashSet::from_iter(updated_operations_types.clone()),
                )
                .await?;

            // Record metrics for each granted permission
            if let Some(ref metrics) = self.metrics {
                for operation in &updated_operations_types {
                    metrics.record_permission_grant(&access.user_id, &format!("{operation:?}"));
                }
            }
        }
        Ok(())
    }

    /// Remove an access authorization for a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn revoke_access(&self, access: &Access, owner: &UserId) -> KResult<()> {
        // if create access right is set, revoke access Create for * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            let co_users = &self.params.crypto_officer.users;
            if !co_users.is_empty() {
                if !co_users.iter().any(|u| u.as_str() == owner.as_str()) {
                    kms_bail!(KmsError::Unauthorized(
                        "Only Crypto Officer users can grant/revoke create access right to a \
                         user."
                            .to_owned()
                    ))
                }
                let user_id = &access.user_id;
                if co_users.contains(user_id) {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "User `{user_id}` is a Crypto Officer — create access right can't be \
                         granted or revoked on their behalf."
                    )))
                }
                let user_id_typed =
                    UserId::try_new(user_id.as_str()).map_err(KmsError::InvalidRequest)?;
                self.database
                    .remove_operations("*", &user_id_typed, HashSet::from([KmipOperation::Create]))
                    .await?;
            }
        }

        if !updated_operations_types.is_empty() {
            let uid = from_request(access.unique_identifier.as_ref(), "RevokeAccess")?.as_str();

            // check the object identified by its `uid` is really owned by `owner`
            if !self.database.is_object_owned_by(uid, owner).await? {
                kms_bail!(KmsError::Unauthorized(format!(
                    "Object with uid `{uid}` is not owned by owner `{owner}`"
                )))
            }

            // check if the owner is trying to revoke itself
            if *owner == access.user_id {
                kms_bail!(KmsError::Unauthorized(
                    "You cannot revoke yourself; you should keep all rights to your objects."
                        .to_owned()
                ))
            }

            let revoke_user_id =
                UserId::try_new(access.user_id.as_str()).map_err(KmsError::InvalidRequest)?;
            self.database
                .remove_operations(
                    uid,
                    &revoke_user_id,
                    HashSet::from_iter(updated_operations_types),
                )
                .await?;
        }
        Ok(())
    }

    /// Get all the access granted for a given object
    /// per user
    pub(crate) async fn list_accesses(
        &self,
        object_id: &UniqueIdentifier,
        owner: &UserId,
    ) -> KResult<Vec<UserAccessResponse>> {
        let object_id = object_id
            .as_str()
            .context("unique_identifier is not a string")?;
        // check the object identified by its `uid` is really owned by `owner`
        // only the owner can list the permission of an object
        if !self.database.is_object_owned_by(object_id, owner).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{object_id}` is not owned by owner `{owner}`"
            )))
        }

        let list = self
            .database
            .list_object_operations_granted(object_id)
            .await?;
        let ids = list
            .into_iter()
            .map(|(user_id, operations)| UserAccessResponse {
                user_id,
                operations: operations.into_iter().collect::<BTreeSet<_>>(),
            })
            .collect();

        Ok(ids)
    }

    /// Get all the objects owned by a given user (the owner)
    pub(crate) async fn list_owned_objects(
        &self,
        owner: &UserId,
    ) -> KResult<Vec<ObjectOwnedResponse>> {
        let list = self
            .database
            .find(None, None, owner, true, self.vendor_id())
            .await?;
        let ids = list.into_iter().map(ObjectOwnedResponse::from).collect();
        Ok(ids)
    }

    /// Get all the access rights granted to a given user
    pub(crate) async fn list_access_rights_obtained(
        &self,
        user: &UserId,
    ) -> KResult<Vec<AccessRightsObtainedResponse>> {
        let list = self.database.list_user_operations_granted(user).await?;
        let ids: Vec<AccessRightsObtainedResponse> = list
            .into_iter()
            .map(|entry| {
                let mut resp = AccessRightsObtainedResponse::from(entry);
                // For HSM keys (not in the objects table), use the HSM
                // routing prefix as owner — avoids leaking admin identities.
                if resp.owner_id.is_empty() {
                    let uid_str = resp.object_id.as_str().unwrap_or_default();
                    if let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(uid_str) {
                        resp.owner_id = prefix.to_owned();
                    }
                }
                resp
            })
            .collect();
        Ok(ids)
    }

    // ─── Operation-level authorization ─────────────────────────────────────

    /// Enforce that the caller has `Create` access-right.
    ///
    /// When `crypto_officer.users` is configured, the user must either:
    /// - have been explicitly granted the `Create` operation on any object,
    /// - be listed in `crypto_officer.users` (active **or** dormant candidate), or
    /// - be the `default_username` (unauthenticated / local access).
    ///
    /// **Applies to**: `Create`, `CreateKeyPair`, `Import`, `Register`, and `Rekey`/`RekeyKeyPair`.
    ///
    /// ## Design notes
    ///
    /// **Dormant candidates pass this gate**: listing a user in `crypto_officer.users`
    /// with `require_ceremony = true` grants them `Create`/`Import`/`Rekey` access even before
    /// the ceremony completes. This is intentional: candidates must create and split a ceremony
    /// key *before* they can activate, so they need `Create` as a ceremony prerequisite. Full
    /// ownership bypass (all other CO privileges) still requires ceremony completion.
    ///
    /// **Rekey is treated as a creation operation**: `Rekey` replaces an existing key with
    /// a newly generated one, which creates a new Managed Object. When `crypto_officer.users` is
    /// configured, object ownership alone does not grant `Rekey` — the caller must also satisfy
    /// this gate (be CO-listed or hold an explicit `Create` grant). This is asymmetric from
    /// `Destroy`/`Revoke`/`SetAttribute`, which rely solely on ownership/grants. The asymmetry is
    /// intentional: Rekey has creation semantics that warrant the same lifecycle gate as `Create`.
    pub(crate) async fn enforce_create_permission(&self, user: &UserId) -> KResult<()> {
        let co_users = &self.params.crypto_officer.users;
        if !co_users.is_empty() {
            if *user == self.params.default_username
                || co_users.iter().any(|u| u == user.as_str())
                || user_has_permission(user, None, &KmipOperation::Create, self).await?
            {
                return Ok(());
            }
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
        // If no Crypto Officer users are configured, all users have the `Create` right.
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

    /// Check whether `user` is allowed to perform `operation` on this object.
    ///
    /// Returns `true` if the user is the owner or has been explicitly granted
    /// the requested operation.
    pub(crate) async fn user_can_perform_operation(
        &self,
        owm: &ObjectWithMetadata,
        user: &UserId,
        operation: &KmipOperation,
    ) -> KResult<bool> {
        if user == owm.owner() {
            return Ok(true);
        }

        // CryptoOfficer bypass: active COs can perform any lifecycle operation on any
        // non-HSM object regardless of ownership (ISO/IEC 19790:2012 §7.4 / NIST SP
        // 800-57 Part 2 Rev 1 §4.3). HSM-backed keys are excluded — they are governed
        // by the HSM admin rules.
        if !ObjectHandle::from(owm.id()).is_hsm() && self.is_crypto_officer(user.as_str()).await? {
            tracing::warn!(
                "CRYPTO_OFFICER_ACCESS: crypto officer {user} bypassed ownership check on {} for {operation:?}",
                owm.id()
            );
            return Ok(true);
        }

        let permissions = self
            .database
            .list_user_operations_on_object(owm.id(), user, false)
            .await?;
        Ok(permissions.contains(operation))
    }

    /// Get the user from the request depending on the authentication method.
    pub(crate) fn get_user(&self, req_http: &HttpRequest) -> UserId {
        if self.params.force_default_username {
            return UserId::from(self.params.default_username.as_str());
        }
        req_http
            .extensions()
            .get::<AuthenticatedUser>()
            .map_or_else(
                || UserId::from(self.params.default_username.as_str()),
                |au| au.username.clone(),
            )
    }

    /// Get the authentication method used for this request, if any.
    pub(crate) fn get_auth_method(
        &self,
        req_http: &HttpRequest,
    ) -> Option<crate::middlewares::AuthMethod> {
        if self.params.force_default_username {
            return None;
        }
        req_http
            .extensions()
            .get::<AuthenticatedUser>()
            .map(|au| au.auth_method)
    }

    /// Returns `true` when `user` currently holds the Crypto Officer role.
    ///
    /// - If `crypto_officer.users` is empty → `false`.
    /// - If `user` is not in `crypto_officer.users` → `false`.
    /// - If `crypto_officer.require_ceremony = true` → checks DB for an active activation record.
    /// - Otherwise → `true` (config-only mode).
    pub(crate) async fn is_crypto_officer(&self, user: &str) -> KResult<bool> {
        let cfg = &self.params.crypto_officer;
        if cfg.users.is_empty() {
            return Ok(false);
        }
        if !cfg.users.iter().any(|u| u == user) {
            return Ok(false);
        }
        if cfg.require_ceremony {
            Ok(self.database.is_crypto_officer_activated_by(user).await?)
        } else {
            Ok(true)
        }
    }
}

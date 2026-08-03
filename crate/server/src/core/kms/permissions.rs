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
    core::{KMS, retrieve_object_utils::user_has_permission, uid_utils::has_prefix},
    error::KmsError,
    kms_bail,
    middlewares::AuthenticatedUser,
    result::{KResult, KResultHelper},
};

impl KMS {
    /// Grant access to a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn grant_access(&self, access: &Access, owner: &str) -> KResult<()> {
        // if create access right is set, grant access to Create for the * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            if let Some(ref users) = self.params.privileged_users {
                if !users.contains(&owner.to_owned()) {
                    kms_bail!(KmsError::Unauthorized(
                        "Only privileged users can grant/revoke create access right to a user."
                            .to_owned()
                    ))
                }
                let user_id = &access.user_id;
                if users.contains(user_id) {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "User `{user_id}` is a privileged user - create access right can't be \
                         granted or revoked."
                    )))
                }
                self.database
                    .grant_operations("*", user_id, HashSet::from([KmipOperation::Create]))
                    .await?;

                // Record metrics for Create permission grant
                if let Some(ref metrics) = self.metrics {
                    metrics.record_permission_grant(user_id, "Create");
                }
            }
        }

        if !updated_operations_types.is_empty() {
            let uid = access
                .unique_identifier
                .as_ref()
                .ok_or(KmsError::UnsupportedPlaceholder)?
                .as_str()
                .context("unique_identifier is not a string")?;

            // check the object identified by its `uid` is really owned by `owner`
            if !self.database.is_object_owned_by(uid, owner).await? {
                kms_bail!(KmsError::Unauthorized(format!(
                    "Object with uid `{uid}` is not owned by owner `{owner}`"
                )))
            }

            // check if an owner is trying to grant themselves
            if owner == access.user_id {
                kms_bail!(KmsError::Unauthorized(
                    "You can't grant yourself, you have already all rights on your own objects"
                        .to_owned()
                ))
            }

            // HSM keys: block granting Destroy and Revoke — these are admin-only operations
            if has_prefix(uid).is_some() {
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

            self.database
                .grant_operations(
                    uid,
                    &access.user_id,
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
    pub(crate) async fn revoke_access(&self, access: &Access, owner: &str) -> KResult<()> {
        // if create access right is set, revoke access Create for * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            if let Some(ref users) = self.params.privileged_users {
                if !users.contains(&owner.to_owned()) {
                    kms_bail!(KmsError::Unauthorized(
                        "Only privileged users can grant/revoke create access right to a user."
                            .to_owned()
                    ))
                }
                let user_id = &access.user_id;
                if users.contains(user_id) {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "User `{user_id}` is a privileged user - create access right can't be \
                         granted or revoked."
                    )))
                }
                self.database
                    .remove_operations("*", user_id, HashSet::from([KmipOperation::Create]))
                    .await?;
            }
        }

        if !updated_operations_types.is_empty() {
            let uid = access
                .unique_identifier
                .as_ref()
                .ok_or(KmsError::UnsupportedPlaceholder)?
                .as_str()
                .context("unique_identifier is not a string")?;

            // check the object identified by its `uid` is really owned by `owner`
            if !self.database.is_object_owned_by(uid, owner).await? {
                kms_bail!(KmsError::Unauthorized(format!(
                    "Object with uid `{uid}` is not owned by owner `{owner}`"
                )))
            }

            // check if the owner is trying to revoke itself
            if owner == access.user_id {
                kms_bail!(KmsError::Unauthorized(
                    "You cannot revoke yourself; you should keep all rights to your objects."
                        .to_owned()
                ))
            }

            self.database
                .remove_operations(
                    uid,
                    &access.user_id,
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
        owner: &str,
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
        owner: &str,
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
        user: &str,
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
                    if let Some(prefix) = has_prefix(uid_str) {
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
    /// When `privileged_users` is configured, the user must either:
    /// - have been explicitly granted the `Create` operation on any object,
    /// - be listed in `privileged_users`, or
    /// - be the `default_username` (unauthenticated / local access).
    ///
    /// This check applies uniformly to `Create`, `CreateKeyPair`, `Import`, and `Register`.
    pub(crate) async fn enforce_create_permission(&self, user: &str) -> KResult<()> {
        if let Some(ref users) = self.params.privileged_users {
            if user == self.params.default_username
                || users.iter().any(|u| u == user)
                || user_has_permission(user, None, &KmipOperation::Create, self).await?
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

    /// Check whether `user` is allowed to perform `operation` on this object.
    ///
    /// Returns `true` if the user is the owner or has been explicitly granted
    /// the requested operation.
    pub(crate) async fn user_can_perform_operation(
        &self,
        owm: &ObjectWithMetadata,
        user: &str,
        operation: &KmipOperation,
    ) -> KResult<bool> {
        if user == owm.owner() {
            return Ok(true);
        }
        let permissions = self
            .database
            .list_user_operations_on_object(owm.id(), user, false)
            .await?;
        Ok(permissions.contains(operation))
    }

    /// Get the user from the request depending on the authentication method.
    pub(crate) fn get_user(&self, req_http: &HttpRequest) -> String {
        if self.params.force_default_username {
            return self.params.default_username.clone();
        }
        req_http
            .extensions()
            .get::<AuthenticatedUser>()
            .map_or_else(
                || self.params.default_username.clone(),
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
}

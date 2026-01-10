use std::collections::{BTreeSet, HashSet};

use actix_web::{HttpMessage, HttpRequest};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation, kmip_types::UniqueIdentifier,
};
use cosmian_logger::debug;

use crate::{
    core::KMS,
    error::KmsError,
    kms_bail,
    middlewares::AuthenticatedUser,
    result::{KResult, KResultHelper},
};

impl KMS {
    /// Grant access to a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn grant_access(
        &self,
        access: &Access,
        owner: &str,
        privileged_users: Option<Vec<String>>,
    ) -> KResult<()> {
        // if create access right is set, grant access to Create for the * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            if let Some(users) = privileged_users {
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
    pub(crate) async fn revoke_access(
        &self,
        access: &Access,
        owner: &str,

        privileged_users: Option<Vec<String>>,
    ) -> KResult<()> {
        // if create access right is set, revoke access Create for * object
        let mut updated_operations_types = access.operation_types.clone();
        if updated_operations_types.contains(&KmipOperation::Create) {
            updated_operations_types.retain(|op| op != &KmipOperation::Create);
            if let Some(users) = privileged_users {
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
        let list = self.database.find(None, None, owner, true).await?;
        let ids = list.into_iter().map(ObjectOwnedResponse::from).collect();
        Ok(ids)
    }

    /// Get all the access rights granted to a given user
    pub(crate) async fn list_access_rights_obtained(
        &self,
        user: &str,
    ) -> KResult<Vec<AccessRightsObtainedResponse>> {
        let list = self.database.list_user_operations_granted(user).await?;
        let ids = list
            .into_iter()
            .map(AccessRightsObtainedResponse::from)
            .collect();
        Ok(ids)
    }

    /// Get the user from the request depending on the authentication method.
    pub(crate) fn get_user(&self, req_http: &HttpRequest) -> String {
        if self.params.force_default_username {
            let default_username = self.params.default_username.clone();
            debug!(
                "Authenticated using forced default user: {}",
                default_username
            );
            return default_username;
        }
        let user = req_http
            .extensions()
            .get::<AuthenticatedUser>()
            .map_or_else(
                || self.params.default_username.clone(),
                |au| au.username.clone(),
            );
        debug!("Authenticated user: {}", user);
        user
    }
}

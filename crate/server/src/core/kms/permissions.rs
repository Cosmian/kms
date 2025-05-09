use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

use actix_web::{HttpMessage, HttpRequest};
use cosmian_kmip::kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
};
use cosmian_kms_interfaces::SessionParams;
use tracing::debug;

use crate::{
    core::KMS,
    error::KmsError,
    kms_bail,
    middlewares::{JwtAuthClaim, PeerCommonName},
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
        params: Option<Arc<dyn SessionParams>>,
        privileged_users: Option<Vec<String>>,
    ) -> KResult<()> {
        // if create access right is set, grant access Create for * object
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
                    .grant_operations(
                        "*",
                        user_id,
                        HashSet::from([KmipOperation::Create]),
                        params.clone(),
                    )
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
            if !self
                .database
                .is_object_owned_by(uid, owner, params.clone())
                .await?
            {
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
                    HashSet::from_iter(updated_operations_types),
                    params,
                )
                .await?;
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
        params: Option<Arc<dyn SessionParams>>,
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
                    .remove_operations(
                        "*",
                        user_id,
                        HashSet::from([KmipOperation::Create]),
                        params.clone(),
                    )
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
            if !self
                .database
                .is_object_owned_by(uid, owner, params.clone())
                .await?
            {
                kms_bail!(KmsError::Unauthorized(format!(
                    "Object with uid `{uid}` is not owned by owner `{owner}`"
                )))
            }

            // check if owner is trying to revoke itself
            if owner == access.user_id {
                kms_bail!(KmsError::Unauthorized(
                    "You can't revoke yourself, you should keep all rights on your own objects"
                        .to_owned()
                ))
            }

            self.database
                .remove_operations(
                    uid,
                    &access.user_id,
                    HashSet::from_iter(updated_operations_types),
                    params,
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
        params: Option<Arc<dyn SessionParams>>,
    ) -> KResult<Vec<UserAccessResponse>> {
        let object_id = object_id
            .as_str()
            .context("unique_identifier is not a string")?;
        // check the object identified by its `uid` is really owned by `owner`
        // only the owner can list the permission of an object
        if !self
            .database
            .is_object_owned_by(object_id, owner, params.clone())
            .await?
        {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{object_id}` is not owned by owner `{owner}`"
            )))
        }

        let list = self
            .database
            .list_object_operations_granted(object_id, params)
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
        params: Option<Arc<dyn SessionParams>>,
    ) -> KResult<Vec<ObjectOwnedResponse>> {
        let list = self.database.find(None, None, owner, true, params).await?;
        let ids = list.into_iter().map(ObjectOwnedResponse::from).collect();
        Ok(ids)
    }

    /// Get all the access rights granted to a given user
    pub(crate) async fn list_access_rights_obtained(
        &self,
        user: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> KResult<Vec<AccessRightsObtainedResponse>> {
        let list = self
            .database
            .list_user_operations_granted(user, params)
            .await?;
        let ids = list
            .into_iter()
            .map(AccessRightsObtainedResponse::from)
            .collect();
        Ok(ids)
    }

    /// Get the user from the request depending on the authentication method
    /// The user is encoded in the JWT `Authorization` header
    /// If the header is not present, the user is extracted from the client certificate
    /// If the client certificate is not present, the user is extracted from the configuration file
    pub(crate) fn get_user(&self, req_http: &HttpRequest) -> String {
        let default_username = self.params.default_username.clone();

        if self.params.force_default_username {
            debug!(
                "Authenticated using forced default user: {}",
                default_username
            );
            return default_username
        }
        // if there is a JWT token, use it in priority
        let user = req_http.extensions().get::<JwtAuthClaim>().map_or_else(
            || {
                req_http
                    .extensions()
                    .get::<PeerCommonName>()
                    .map_or(default_username, |claim| claim.common_name.clone())
            },
            |claim| claim.email.clone(),
        );
        debug!("Authenticated user: {}", user);
        user
    }
}

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};

use super::object_with_metadata::ObjectWithMetadata;
use crate::result::KResult;

#[async_trait(?Send)]
pub trait Database {
    /// Return the filename of the database or `None` if not supported
    fn filename(&self, group_id: u128) -> Option<PathBuf>;

    /// Insert the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier>;

    /// Insert the provided Objects in the database in a transaction
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, Object, &HashSet<String>)],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>>;

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    ///
    /// The `query_access_grant` allows additional filtering in the `access` table to see
    /// if a `user`, that is not a owner, has the corresponding access granted
    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>>;

    /// Retrieve the ags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Upsert (update or create if does not exist)
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        tags: &HashSet<String>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Delete an object from the database.
    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// List all the access rights obtained by `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, is_wrapped)
    /// where `operations` is a list of operations that `user` can perform on the object
    /// and `is_wrapped` is a boolean indicating if the object is wrapped
    async fn list_access_rights_obtained(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationType>,
            IsWrapped,
        )>,
    >;

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_accesses(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>>;

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>>;

    #[cfg(test)]
    async fn perms(
        &self,
        uid: &str,
        userid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOperationType>>;
}

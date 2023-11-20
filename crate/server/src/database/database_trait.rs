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
    /// Object is a triplet:
    /// - optional uid
    /// - KMIP object
    /// - tags
    ///
    /// A new uid will be created if none is supplied.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    /// //TODO: this should be deprecated in favor of atomic()
    async fn create_objects(
        &self,
        owner: &str,
        objects: Vec<(Option<String>, Object, &HashSet<String>)>,
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

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &UniqueIdentifier,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &UniqueIdentifier,
        object: &Object,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &UniqueIdentifier,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Upsert (update or create if does not exist)
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn upsert(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Delete an object from the database.
    async fn delete(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// List all the access rights granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, is_wrapped)
    /// where `operations` is a list of operations that `user` can perform on the object
    async fn list_user_granted_access_rights(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<UniqueIdentifier, (String, StateEnumeration, HashSet<ObjectOperationType>)>>;

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_object_accesses_granted(
        &self,
        uid: &UniqueIdentifier,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>>;

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_access(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_access(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &UniqueIdentifier,
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

    /// List all the access rights that have been granted to a user on an object
    ///
    /// These access rights may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    async fn list_user_access_rights_on_object(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>>;

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    async fn atomic(
        &self,
        owner: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;
}

/// An atomic operation on the database
#[derive(Debug)]
#[allow(dead_code)]
pub enum AtomicOperation {
    /// Create (uid, object, tags) - the state will be active
    Create((String, Object, HashSet<String>)),
    /// Upsert (uid, object, tags, state) - the state be updated
    Upsert((String, Object, Option<HashSet<String>>, StateEnumeration)),
    /// Update the object (uid, object, tags, state) - the state will be not be updated
    UpdateObject((String, Object, Option<HashSet<String>>)),
    /// Update the state (uid, state)
    UpdateState((String, StateEnumeration)),
    /// Delete (uid)
    Delete(String),
}

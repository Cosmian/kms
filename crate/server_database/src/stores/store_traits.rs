//! Traits that must be implemented by all the stores (DBs, HSMs, etc.) that store objects
//! and/or permissions
//TODO These traits must be moved to the `interfaces` crate,
// as soon as the KMIP crate is refactored to NOT pull the openssl dependency

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
    KmipOperation,
};

use crate::{error::DbResult, stores::ExtraStoreParams, ObjectWithMetadata};

/// An atomic operation on the objects database
pub enum AtomicOperation {
    /// Create (uid, object, attributes, tags) - the state will be active
    Create((String, Object, Attributes, HashSet<String>)),
    // /// Upsert (uid, object, attributes, tags, state) - the state be updated
    Upsert(
        (
            String,
            Object,
            Attributes,
            Option<HashSet<String>>,
            StateEnumeration,
        ),
    ),
    /// Update the object (uid, object, attributes, tags) - the state will be not be updated
    UpdateObject((String, Object, Attributes, Option<HashSet<String>>)),
    /// Update the state (uid, state)
    UpdateState((String, StateEnumeration)),
    /// Delete (uid)
    Delete(String),
}

impl AtomicOperation {
    pub(crate) fn get_object_uid(&self) -> &str {
        match self {
            Self::Create((uid, _, _, _))
            | Self::Upsert((uid, _, _, _, _))
            | Self::UpdateObject((uid, _, _, _))
            | Self::UpdateState((uid, _))
            | Self::Delete(uid) => uid,
        }
    }
}

/// Trait that must implement all object stores (DBs, HSMs, etc.) that store objects
#[async_trait(?Send)]
pub trait ObjectsStore {
    /// Return the filename of the database or `None` if not supported
    fn filename(&self, group_id: u128) -> Option<PathBuf>;

    /// Migrate the database to the latest version
    async fn migrate(&self, params: Option<&ExtraStoreParams>) -> DbResult<()>;

    /// Create the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<String>;

    /// Retrieve an object from the database.
    async fn retrieve(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>>;

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()>;

    /// Delete an object from the database.
    #[allow(dead_code)]
    async fn delete(&self, uid: &str, params: Option<&ExtraStoreParams>) -> DbResult<()>;

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    ///
    /// # Returns
    /// The list objects uid that operations were performed on
    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<String>>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<bool>;

    /// List the `uid` of all the objects that have the given `tags`
    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<(String, StateEnumeration, Attributes)>>;
}

/// Trait that the stores must implement to store permissions
#[async_trait(?Send)]
pub(crate) trait PermissionsStore {
    /// List all the KMIP operations granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, is_wrapped)
    /// where `operations` is a list of operations that `user` can perform on the object
    async fn list_user_operations_granted(
        &self,
        user: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>>;

    /// List all the KMIP operations granted per `user`
    /// This is called by the owner only
    async fn list_object_operations_granted(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>>;

    /// Grant to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()>;

    /// Remove to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()>;

    /// List all the KMIP operations that have been granted to a user on an object
    ///
    /// These operations may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<KmipOperation>>;
}

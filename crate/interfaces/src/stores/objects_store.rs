use std::collections::HashSet;

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{kmip_attributes::Attributes, kmip_objects::Object},
};

use crate::{InterfaceResult, ObjectWithMetadata};
use crate::{InterfaceResult, ObjectWithMetadata};

/// An atomic operation on the objects database
pub enum AtomicOperation {
    /// Create (uid, object, attributes, tags) - the state will be active
    Create((String, Object, Attributes, HashSet<String>)),
    /// Upsert (uid, object, attributes, tags, state) - the state be updated
    Upsert((String, Object, Attributes, Option<HashSet<String>>, State)),
    /// Update the object (uid, object, attributes, tags) - the state will be not be updated
    UpdateObject((String, Object, Attributes, Option<HashSet<String>>)),
    /// Update the state (uid, state)
    UpdateState((String, State)),
    /// Delete (uid)
    Delete(String),
}

impl AtomicOperation {
    #[must_use]
    pub fn get_object_uid(&self) -> &str {
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
    ) -> InterfaceResult<String>;

    /// Retrieve an object from the database.
    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>>;
    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>>;

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>>;
    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()>;
    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()>;

    /// Delete an object from the database.
    async fn delete(&self, uid: &str) -> InterfaceResult<()>;
    async fn delete(&self, uid: &str) -> InterfaceResult<()>;

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    ///
    /// # Returns
    /// The list objects uid that operations were performed on
    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool>;
    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool>;

    /// List the `uid` of all the objects that have the given `tags`
    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>>;
    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>>;
}

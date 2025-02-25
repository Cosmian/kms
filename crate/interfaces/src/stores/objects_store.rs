use std::{collections::HashSet, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use serde::{Deserialize, Serialize};

use crate::{InterfaceResult, ObjectWithMetadata, stores::SessionParams};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub enum DbState {
    Ready,
    Upgrading,
}

/// An atomic operation on the objects database
pub enum AtomicOperation {
    /// Create (uid, object, attributes, tags) - the state will be active
    Create((String, Object, Attributes, HashSet<String>)),
    /// Upsert (uid, object, attributes, tags, state) - the state be updated
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
    /// Return the filename of the database or `None` if not supported
    fn filename(&self, group_id: u128) -> Option<PathBuf>;

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
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String>;

    /// Retrieve an object from the database.
    async fn retrieve(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>>;

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()>;

    /// Delete an object from the database.
    #[allow(dead_code)]
    async fn delete(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()>;

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    ///
    /// # Returns
    /// The list objects uid that operations were performed on
    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool>;

    /// List the `uid` of all the objects that have the given `tags`
    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, StateEnumeration, Attributes)>>;
}

use std::collections::HashSet;

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{kmip_attributes::Attributes, kmip_objects::Object},
};

use cosmian_logger::warn;

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

    /// Retrieve the tags of the object with the given `uid`
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

    /// Delete an object from the database.
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

    /// List the `uid` of all the objects that have the given `tags`
    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>>;

    /// Count all objects that are **not** in a terminal (destroyed) state.
    ///
    /// # Purpose — metrics only
    ///
    /// This method is called exclusively by the OTEL metrics layer to feed the
    /// `kms.objects.total` gauge. It deliberately skips all user/permission
    /// filters so the result reflects the true server-wide object inventory,
    /// not just the subset visible to a particular caller.
    ///
    /// **Never expose the result to client requests** — it bypasses access control.
    ///
    /// # Why a default of `Ok(0)`?
    ///
    /// Adding a required method to this trait would force every backend
    /// (SQL, Redis, HSM stubs) to implement it in the same commit. The default
    /// lets backends compile immediately; each one should replace it with a
    /// real implementation when ready. A `TODO` comment is added at each
    /// call site that still uses the default.
    async fn count_all_non_destroyed(&self) -> InterfaceResult<u64> {
        warn!(
            "count_all_non_destroyed not implemented for this ObjectsStore backend — \
             kms.objects.total will read 0 until a real implementation is provided"
        );
        Ok(0)
    }
}

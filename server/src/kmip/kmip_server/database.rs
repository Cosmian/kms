use async_trait::async_trait;
use cosmian_kmip::kmip::{
    access::ObjectOperationTypes,
    kmip_objects::{Object, ObjectType},
    kmip_types::{StateEnumeration, UniqueIdentifier},
};
use serde::{Deserialize, Serialize};

use crate::{kms_bail, result::KResult};

#[async_trait]
pub(crate) trait Database {
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
    ) -> KResult<UniqueIdentifier>;

    /// Insert the provided Objects in the database in a transaction
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, Object)],
    ) -> KResult<Vec<UniqueIdentifier>>;

    /// Retrieve an object from the database using `uid` and `owner`.
    /// The `query_read_access` allows additional lookup in `read_access` table to see
    /// if `owner` is matching `read_access` authorization
    async fn retrieve(
        &self,
        uid: &str,
        owner: &str,
        query_read_access: ObjectOperationTypes,
    ) -> KResult<Option<(Object, StateEnumeration)>>;

    async fn update_object(&self, uid: &str, owner: &str, object: &Object) -> KResult<()>;

    async fn update_state(&self, uid: &str, owner: &str, state: StateEnumeration) -> KResult<()>;

    /// upsert (update or create if not exsits)
    async fn upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &Object,
        state: StateEnumeration,
    ) -> KResult<()>;

    async fn delete(&self, uid: &str, owner: &str) -> KResult<()>;

    async fn list(&self, owner: &str) -> KResult<Vec<(UniqueIdentifier, StateEnumeration)>>;

    /// Insert a `userid` to give `operation_type` access right for the object identified
    /// by its `uid` and belonging to `owner`
    async fn insert_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
    ) -> KResult<()>;

    /// Delete a `userid` to remove read access right for the object identified
    /// by its `uid` and belonging to `owner`
    async fn delete_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
    ) -> KResult<()>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> KResult<bool>;
}

/// The Database implemented using `SQLite`
///
/// This class uses a connection should be cloned on each server thread
#[derive(Clone)]
/// When using JSON serialization, the Object is untagged
/// and looses its type information, so we have to keep
/// the `ObjectType`. See `Object` anf `post_fix()` for details
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DBObject {
    pub(crate) object_type: ObjectType,
    pub(crate) object: Object,
}

pub fn state_from_string(s: &str) -> KResult<StateEnumeration> {
    match s {
        "PreActive" => Ok(StateEnumeration::PreActive),
        "Active" => Ok(StateEnumeration::Active),
        "Deactivated" => Ok(StateEnumeration::Deactivated),
        "Compromised" => Ok(StateEnumeration::Compromised),
        "Destroyed" => Ok(StateEnumeration::Destroyed),
        "Destroyed_Compromised" => Ok(StateEnumeration::Destroyed_Compromised),
        x => kms_bail!("invalid state in db: {}", x),
    }
}

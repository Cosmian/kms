use std::{collections::HashSet, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cosmian_findex_redis::{FindexError, FindexRedis, Location, RemovedLocationsFinder};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{object_with_metadata::ObjectWithMetadata, Database};
use crate::result::KResult;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedisDbObject {
    #[serde(rename = "o")]
    object: Object,
    #[serde(rename = "w")]
    owner: String,
    #[serde(rename = "s")]
    state: StateEnumeration,
}

struct ObjectsDB {
    mgr: ConnectionManager,
}

impl ObjectsDB {
    pub async fn new(mgr: ConnectionManager) -> KResult<Self> {
        Ok(Self { mgr })
    }

    pub async fn upsert(
        &self,
        uid: &str,
        object: &Object,
        owner: &str,
        state: StateEnumeration,
    ) -> KResult<()> {
        let dbo = RedisDbObject {
            object: object.clone(),
            owner: owner.to_string(),
            state,
        };
        self.mgr
            .clone()
            .set(uid, serde_json::to_string(&dbo)?)
            .await?;
        Ok(())
    }

    pub async fn get(&self, uid: &str) -> KResult<Object> {
        todo!()
    }
}

#[async_trait]
impl RemovedLocationsFinder for ObjectsDB {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        Ok(HashSet::new())
    }
}

struct RedisWithFindex {
    db: Arc<ObjectsDB>,
    findex: FindexRedis,
}

impl RedisWithFindex {
    pub async fn new(redis_url: &str) -> KResult<RedisWithFindex> {
        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;
        let db = Arc::new(ObjectsDB::new(mgr.clone()).await?);
        let findex = FindexRedis::connect_with_manager(mgr.clone(), db.clone()).await?;
        Ok(Self { db, findex })
    }
}

#[async_trait]
impl Database for RedisWithFindex {
    /// Return the filename of the database if supported
    fn filename(&self, _group_id: u128) -> PathBuf {
        PathBuf::from("")
    }

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
    ) -> KResult<UniqueIdentifier> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

        todo!()
    }

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
    ) -> KResult<Vec<UniqueIdentifier>> {
        todo!()
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    ///
    /// The `query_read_access` allows additional filtering in `read_access` table to see
    /// if a `user`, that is not a user, has the corresponding `read_access` authorization
    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_read_access: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectWithMetadata>> {
        todo!()
    }

    /// Retrieve the ags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        todo!()
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

    /// upsert (update or create if not exists)
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        tags: &HashSet<String>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

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
    > {
        todo!()
    }

    async fn list_accesses(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationType>)>> {
        todo!()
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        todo!()
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        todo!()
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        todo!()
    }

    #[cfg(test)]
    async fn perms(
        &self,
        uid: &str,
        userid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOperationType>> {
        todo!()
    }
}

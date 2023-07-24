use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::kdf;
use cosmian_findex_redis::{
    FindexError, FindexRedis, IndexedValue, Keyword, Location, RemovedLocationsFinder,
    MASTER_KEY_LENGTH,
};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};
use futures::lock::Mutex;
use redis::{aio::ConnectionManager, pipe, AsyncCommands};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{object_with_metadata::ObjectWithMetadata, Database};
use crate::{
    kms_error,
    result::{KResult, KResultHelper},
};

fn intersect_all<I: IntoIterator<Item = HashSet<Location>>>(sets: I) -> HashSet<Location> {
    let mut iter = sets.into_iter();
    let first = iter.next().unwrap_or_default();
    iter.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedisDbObject {
    #[serde(rename = "o")]
    object: Object,
    #[serde(rename = "t")]
    object_type: ObjectType,
    #[serde(rename = "w")]
    owner: String,
    #[serde(rename = "s")]
    state: StateEnumeration,
    #[serde(rename = "l")]
    tags: HashSet<String>,
}

impl RedisDbObject {
    pub fn new(
        object: Object,
        owner: String,
        state: StateEnumeration,
        tags: HashSet<String>,
    ) -> Self {
        let object_type = object.object_type();
        Self {
            object,
            object_type,
            owner,
            state,
            tags,
        }
    }

    pub fn keywords(&self) -> HashSet<Keyword> {
        let mut keywords = self
            .tags
            .iter()
            .map(|tag| Keyword::from(tag.as_bytes()))
            .collect::<HashSet<Keyword>>();
        // index some of the attributes
        if let Ok(attributes) = self.object.attributes() {
            if let Some(algo) = attributes.cryptographic_algorithm {
                keywords.insert(Keyword::from(algo.to_string().as_bytes()));
            }
            if let Some(key_format_type) = attributes.key_format_type {
                keywords.insert(Keyword::from(key_format_type.to_string().as_bytes()));
            }
            if let Some(cryptographic_length) = attributes.cryptographic_length {
                keywords.insert(Keyword::from(cryptographic_length.to_be_bytes().as_slice()));
            }
        }
        // index the owner
        keywords.insert(Keyword::from(self.owner.as_bytes()));
        keywords
    }
}

const DB_KEY_LENGTH: usize = 32;

struct ObjectsDB {
    mgr: ConnectionManager,
}

impl ObjectsDB {
    pub async fn new(mgr: ConnectionManager) -> KResult<Self> {
        Ok(Self { mgr })
    }

    fn object_key(uid: &str) -> String {
        format!("do::{}", uid)
    }

    pub async fn object_upsert(&self, uid: &str, redis_db_object: &RedisDbObject) -> KResult<()> {
        self.mgr
            .clone()
            .set(
                ObjectsDB::object_key(uid),
                serde_json::to_vec(redis_db_object)?,
            )
            .await?;
        Ok(())
    }

    pub async fn object_get(&self, uid: &str) -> KResult<RedisDbObject> {
        let bytes: Vec<u8> = self.mgr.clone().get(ObjectsDB::object_key(uid)).await?;
        let mut dbo: RedisDbObject = serde_json::from_slice(&bytes)?;
        dbo.object = Object::post_fix(dbo.object_type, dbo.object);
        Ok(dbo)
    }

    pub async fn object_delete(&self, uid: &str) -> KResult<()> {
        self.mgr.clone().del(ObjectsDB::object_key(uid)).await?;
        Ok(())
    }

    pub async fn objects_upsert(&self, objects: &HashMap<String, RedisDbObject>) -> KResult<()> {
        let mut pipeline = pipe();
        for (uid, redis_db_object) in objects.iter() {
            pipeline.set(
                ObjectsDB::object_key(uid),
                serde_json::to_vec(redis_db_object)?,
            );
        }
        pipeline.query_async(&mut self.mgr.clone()).await?;
        Ok(())
    }

    pub async fn objects_get(
        &self,
        uids: &HashSet<String>,
    ) -> KResult<HashMap<String, RedisDbObject>> {
        let mut pipeline = pipe();
        for uid in uids.iter() {
            pipeline.get(ObjectsDB::object_key(uid));
        }
        let bytes: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;
        let mut results = HashMap::new();
        for (uid, bytes) in uids.iter().zip(bytes) {
            let mut dbo: RedisDbObject = serde_json::from_slice(&bytes)?;
            dbo.object = Object::post_fix(dbo.object_type, dbo.object);
            results.insert(uid.to_string(), dbo);
        }
        Ok(results)
    }

    fn permissions_key(uid: &str, user_id: &str) -> String {
        format!("dp::{}::{}", uid, user_id)
    }

    pub async fn list_user_permissions(
        &self,
        user_id: &str,
    ) -> KResult<HashMap<String, Vec<ObjectOperationType>>> {
        let wildcard = format!("dp::*::{}", user_id);
        let keys: Vec<String> = self.mgr.clone().keys(&wildcard).await?;
        // recover the corresponding permissions
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(&keys).await?;
        keys.into_iter()
            .zip(values)
            .map(|(k, v)| {
                let uid = k.replace(&wildcard, "");
                let permissions: HashSet<ObjectOperationType> = serde_json::from_slice(&v)?;
                Ok((uid, permissions.into_iter().collect()))
            })
            .collect::<KResult<HashMap<String, Vec<ObjectOperationType>>>>()
    }

    pub async fn permissions_upsert(
        &self,
        uid: &str,
        user_id: &str,
        permissions: HashSet<ObjectOperationType>,
    ) -> KResult<()> {
        self.mgr
            .clone()
            .set(
                ObjectsDB::permissions_key(uid, user_id),
                serde_json::to_vec(&permissions)?,
            )
            .await?;
        Ok(())
    }

    pub async fn permissions_get(
        &self,
        uid: &str,
        user_id: &str,
    ) -> KResult<HashSet<ObjectOperationType>> {
        let bytes: Vec<u8> = self
            .mgr
            .clone()
            .get(ObjectsDB::permissions_key(uid, user_id))
            .await?;
        let permissions: HashSet<ObjectOperationType> = serde_json::from_slice(&bytes)?;
        Ok(permissions)
    }

    pub async fn permissions_delete(&self, uid: &str, user_id: &str) -> KResult<()> {
        self.mgr
            .clone()
            .del(ObjectsDB::permissions_key(uid, user_id))
            .await?;
        Ok(())
    }

    /// Clear all data
    ///
    /// # Warning
    /// This is definitive
    pub async fn clear_all(&self) -> KResult<()> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.mgr.clone())
            .await?;
        Ok(())
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

pub struct RedisWithFindex {
    db: Arc<ObjectsDB>,
    //TODO this Mutex should not be here; Findex needs to be changed to be thread-safe and not take &mut self
    findex: Mutex<FindexRedis>,
    findex_key: [u8; MASTER_KEY_LENGTH],
    db_key: [u8; DB_KEY_LENGTH],
    label: Vec<u8>,
}

impl RedisWithFindex {
    pub async fn new(
        redis_url: &str,
        master_key: &[u8; 32],
        label: &[u8],
    ) -> KResult<RedisWithFindex> {
        let findex_key = kdf!(MASTER_KEY_LENGTH, master_key);
        let db_key = kdf!(DB_KEY_LENGTH, master_key);

        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;
        let db = Arc::new(ObjectsDB::new(mgr.clone()).await?);
        let findex = Mutex::new(FindexRedis::connect_with_manager(mgr.clone(), db.clone()).await?);
        Ok(Self {
            db,
            findex,
            findex_key,
            db_key,
            label: label.to_vec(),
        })
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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let indexed_value = IndexedValue::Location(Location::from(uid.as_bytes()));

        // the database object to index and store
        let db_object = RedisDbObject::new(
            object.clone(),
            owner.to_string(),
            StateEnumeration::Active,
            tags.clone(),
        );

        // extract the keywords
        let keywords = db_object.keywords();

        // additions to the index
        let mut additions = HashMap::new();
        additions.insert(indexed_value, keywords);

        //upsert the index
        self.findex
            .lock()
            .await
            // .expect("findex lock is poisoned")
            .upsert(&self.findex_key, &self.label, additions, HashMap::new())
            .await?;

        // upsert the object
        self.db
            .object_upsert(
                &uid,
                &RedisDbObject::new(
                    object.clone(),
                    owner.to_string(),
                    StateEnumeration::Active,
                    tags.clone(),
                ),
            )
            .await?;

        Ok(UniqueIdentifier::from(uid))
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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        // If the uid is not provided, generate a new one
        let mut uids = vec![];
        let mut additions = HashMap::new();
        let mut db_objects = HashMap::new();
        for (uid, object, tags) in objects.iter() {
            let uid = uid.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
            let indexed_value = IndexedValue::Location(Location::from(uid.as_bytes()));

            // the database object to index and store
            let db_object = RedisDbObject::new(
                object.clone(),
                owner.to_string(),
                StateEnumeration::Active,
                (*tags).clone(),
            );

            // extract the keywords
            let keywords = db_object.keywords();

            // additions to the index
            additions.insert(indexed_value, keywords);

            //upsert the object
            db_objects.insert(uid.clone(), db_object);
            uids.push(uid);
        }

        //upsert the indexes
        self.findex
            .lock()
            .await
            // .expect("findex lock is poisoned")
            .upsert(&self.findex_key, &self.label, additions, HashMap::new())
            .await?;

        // upsert the objects
        self.db.objects_upsert(&db_objects).await?;

        Ok(uids.into_iter().map(UniqueIdentifier::from).collect())
    }

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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectWithMetadata>> {
        let uids = if uid_or_tags.starts_with('[') {
            let tags: HashSet<String> = serde_json::from_str(uid_or_tags)
                .with_context(|| format!("Invalid tags: {uid_or_tags}"))?;
            let keywords = tags
                .iter()
                .map(|tag| Keyword::from(tag.as_bytes()))
                .collect::<HashSet<Keyword>>();
            // find the locations that match at least one of the tags
            let res = self
                .findex
                .lock()
                .await
                .search(&self.findex_key, &self.label, keywords)
                .await?;
            // we want the intersection of all the locations
            let locations = intersect_all(res.values().cloned());
            locations
                .into_iter()
                .map(|location| {
                    String::from_utf8(location.to_vec()).map_err(|_| kms_error!("Invalid uid"))
                })
                .collect::<KResult<HashSet<String>>>()?
        } else {
            HashSet::from([uid_or_tags.to_string()])
        };

        // now retrieve the object
        let results = self.db.objects_get(&uids).await?;
        let mut objects: Vec<ObjectWithMetadata> = vec![];
        for (uid, redis_db_object) in results {
            // if the user is the owner, return it
            if redis_db_object.owner == user {
                objects.push(ObjectWithMetadata {
                    id: uid,
                    object: redis_db_object.object,
                    owner: redis_db_object.owner,
                    state: redis_db_object.state,
                    permissions: vec![],
                });
                continue
            }

            // fetch the permissions for the user
            let permissions = self
                .db
                .permissions_get(&uid, user)
                .await
                .unwrap_or_default();
            if permissions.contains(&query_access_grant) {
                objects.push(ObjectWithMetadata {
                    id: uid,
                    object: redis_db_object.object,
                    owner: redis_db_object.owner,
                    state: redis_db_object.state,
                    permissions: permissions.into_iter().collect(),
                });
            }
        }
        Ok(objects)
    }

    /// Retrieve the ags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        let redis_db_object = self.db.object_get(uid).await?;
        Ok(redis_db_object.tags)
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut db_object = self.db.object_get(uid).await?;
        db_object.object = object.clone();
        if let Some(tags) = tags {
            db_object.tags = tags.clone();
        }
        self.db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut db_object = self.db.object_get(uid).await?;
        db_object.state = state;
        self.db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    /// upsert (update or create if not exists)
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        tags: &HashSet<String>,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = RedisDbObject::new(object.clone(), user.to_string(), state, tags.clone());
        self.db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = self.db.object_get(uid).await?;
        if db_object.owner != user {
            return Err(kms_error!("User is not the owner of the object"))
        }
        self.db.object_delete(uid).await?;
        Ok(())
    }

    async fn list_access_rights_obtained(
        &self,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationType>,
            IsWrapped,
        )>,
    > {
        let permissions = self.db.list_user_permissions(user).await?;
        let redis_db_objects = self
            .db
            .objects_get(
                &permissions
                    .keys()
                    .map(|uid| uid.to_owned())
                    .collect::<HashSet<String>>(),
            )
            .await?;
        Ok(permissions
            .into_iter()
            .zip(redis_db_objects)
            .map(|((uid, permissions), (_, redis_db_object))| {
                (
                    UniqueIdentifier::from(uid),
                    redis_db_object.owner,
                    redis_db_object.state,
                    permissions,
                    false, // TODO: de-hardcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
                )
            })
            .collect())
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_findex_redis::Location;
    use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration};
    use cosmian_kms_utils::{access::ObjectOperationType, crypto::symmetric::create_symmetric_key};
    use redis::aio::ConnectionManager;
    use serial_test::serial;
    use tracing::trace;

    use crate::{
        database::redis_with_findex::{ObjectsDB, RedisDbObject},
        log_utils::log_init,
        result::KResult,
    };

    const REDIS_URL: &str = "redis://localhost:6379";

    #[test]
    fn test_intersect() {
        let set1: HashSet<_> = vec![
            Location::from(b"1".as_slice()),
            Location::from(b"2".as_slice()),
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
        ]
        .into_iter()
        .collect();
        let set2: HashSet<_> = vec![
            Location::from(b"2".as_slice()),
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
            Location::from(b"5".as_slice()),
        ]
        .into_iter()
        .collect();
        let set3: HashSet<_> = vec![
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
            Location::from(b"5".as_slice()),
            Location::from(b"6".as_slice()),
        ]
        .into_iter()
        .collect();

        let sets = vec![set1, set2, set3];
        let res = super::intersect_all(sets);
        assert_eq!(res.len(), 2);
        assert!(res.contains(&Location::from(b"3".as_slice())));
        assert!(res.contains(&Location::from(b"4".as_slice())));
    }

    #[actix_web::test]
    #[serial]
    pub async fn test_objects_db() -> KResult<()> {
        log_init("test_objects_db=trace");
        trace!("test_objects_db");

        let client = redis::Client::open(REDIS_URL)?;
        let mgr = ConnectionManager::new(client).await?;

        let o_db = ObjectsDB::new(mgr.clone()).await?;

        // single upsert - get - delete
        let uid = "test_objects_db";

        let mut rng = CsRng::from_entropy();
        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let object = create_symmetric_key(&symmetric_key, CryptographicAlgorithm::AES);

        // clean up
        o_db.clear_all().await?;

        // check that the object is not there
        assert!(o_db.object_get(uid).await.is_err());

        o_db.object_upsert(
            uid,
            &RedisDbObject::new(
                object.clone(),
                "owner".to_string(),
                StateEnumeration::Active,
                HashSet::new(),
            ),
        )
        .await?;
        let redis_db_object = o_db.object_get(uid).await?;
        assert_eq!(
            object.key_block()?.key_bytes()?,
            redis_db_object.object.key_block()?.key_bytes()?
        );
        assert_eq!(redis_db_object.owner, "owner");
        assert_eq!(redis_db_object.state, StateEnumeration::Active);

        o_db.object_delete(uid).await?;
        assert!(o_db.object_get(uid).await.is_err());

        Ok(())
    }

    #[actix_web::test]
    #[serial]
    pub async fn test_permissions_db() -> KResult<()> {
        log_init("test_permissions_db=trace");
        trace!("test_permissions_db");

        let client = redis::Client::open(REDIS_URL)?;
        let mgr = ConnectionManager::new(client).await?;

        let o_db = ObjectsDB::new(mgr.clone()).await?;

        // single upsert - get - delete
        let uid = "test_permissions_db";
        let user_id = "user";

        let permissions =
            HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt]);

        // clean up
        o_db.clear_all().await?;

        // check that the permissions is not there
        assert!(o_db.permissions_get(uid, user_id).await.is_err());

        o_db.permissions_upsert(uid, user_id, permissions.clone())
            .await?;
        let permissions2 = o_db.permissions_get(uid, user_id).await?;
        assert_eq!(permissions2, permissions);

        o_db.permissions_delete(uid, user_id).await?;
        assert!(o_db.permissions_get(uid, user_id).await.is_err());

        Ok(())
    }
}

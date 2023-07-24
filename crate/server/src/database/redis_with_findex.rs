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
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{object_with_metadata::ObjectWithMetadata, Database};
use crate::{
    kms_bail, kms_error,
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

    pub async fn object_upsert(
        &self,
        uid: &str,
        object: &Object,
        owner: &str,
        state: StateEnumeration,
        tags: &HashSet<String>,
    ) -> KResult<()> {
        let dbo = RedisDbObject {
            object: object.clone(),
            object_type: object.object_type(),
            owner: owner.to_string(),
            state,
            tags: tags.clone(),
        };
        self.mgr
            .clone()
            .set(ObjectsDB::object_key(uid), serde_json::to_vec(&dbo)?)
            .await?;
        Ok(())
    }

    pub async fn object_get(
        &self,
        uid: &str,
    ) -> KResult<(Object, String, StateEnumeration, HashSet<String>)> {
        let bytes: Vec<u8> = self.mgr.clone().get(ObjectsDB::object_key(uid)).await?;
        let mut dbo: RedisDbObject = serde_json::from_slice(&bytes)?;
        dbo.object = Object::post_fix(dbo.object_type, dbo.object);
        Ok((dbo.object, dbo.owner, dbo.state, dbo.tags))
    }

    pub async fn object_delete(&self, uid: &str) -> KResult<()> {
        self.mgr.clone().del(ObjectsDB::object_key(uid)).await?;
        Ok(())
    }

    fn permissions_key(uid: &str, user_id: &str) -> String {
        format!("dp::{}::{}", uid, user_id)
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

        // create the indexes
        // tags
        let mut keywords = tags
            .iter()
            .map(|tag| Keyword::from(tag.as_bytes()))
            .collect::<HashSet<Keyword>>();
        // index some of the attributes
        if let Ok(attributes) = object.attributes() {
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
        keywords.insert(Keyword::from(owner.as_bytes()));
        // additions
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
            .object_upsert(&uid, object, owner, StateEnumeration::Active, tags)
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
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        todo!()
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
        let uid = if uid_or_tags.starts_with('[') {
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
            if locations.len() > 1 {
                kms_bail!("Too many objects found for tags: {:?}", tags)
            }
            let location = locations
                .into_iter()
                .next()
                .ok_or_else(|| kms_error!("No object found for tags: {:?}", tags))?
                .to_vec();
            String::from_utf8(location).map_err(|_| kms_error!("Invalid uid"))?
        } else {
            uid_or_tags.to_string()
        };

        // now retrieve the object
        let (object, owner, state, _tags) = self.db.object_get(&uid).await?;

        // if the user is the owner, return it
        if owner == user {
            return Ok(vec![ObjectWithMetadata {
                id: uid,
                object,
                owner,
                state,
                permissions: vec![],
            }])
        }

        // fetch the permissions for the user
        let permissions = self
            .db
            .permissions_get(&uid, user)
            .await
            .unwrap_or_default();
        if permissions.contains(&query_access_grant) {
            Ok(vec![ObjectWithMetadata {
                id: uid,
                object,
                owner,
                state,
                permissions: permissions.into_iter().collect(),
            }])
        } else {
            kms_bail!("User {user} does not have the required access to object {uid}")
        }
    }

    /// Retrieve the ags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        let (_object, _owner, _state, tags) = self.db.object_get(uid).await?;
        Ok(tags)
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

    use crate::{database::redis_with_findex::ObjectsDB, log_utils::log_init, result::KResult};

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
            &object,
            "owner",
            StateEnumeration::Active,
            &HashSet::new(),
        )
        .await?;
        let (object2, owner, state, _tags) = o_db.object_get(uid).await?;
        assert_eq!(
            object.key_block()?.key_bytes()?,
            object2.key_block()?.key_bytes()?
        );
        assert_eq!(owner, "owner");
        assert_eq!(state, StateEnumeration::Active);

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

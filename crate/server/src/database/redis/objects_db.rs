use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_findex_redis::{FindexError, Keyword, Location, RemovedLocationsFinder};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_utils::access::ObjectOperationType;
use redis::{aio::ConnectionManager, pipe, AsyncCommands, ErrorKind, Pipeline};
use serde::{Deserialize, Serialize};

use crate::{result::KResult, transaction_async};

/// Extract the keywords from the attributes
pub(crate) fn keywords_from_attributes(attributes: &Attributes) -> HashSet<Keyword> {
    let mut keywords = HashSet::new();
    if let Some(algo) = attributes.cryptographic_algorithm {
        keywords.insert(Keyword::from(algo.to_string().as_bytes()));
    }
    if let Some(key_format_type) = attributes.key_format_type {
        keywords.insert(Keyword::from(key_format_type.to_string().as_bytes()));
    }
    if let Some(cryptographic_length) = attributes.cryptographic_length {
        keywords.insert(Keyword::from(cryptographic_length.to_be_bytes().as_slice()));
    }
    if let Some(links) = &attributes.link {
        for link in links {
            match serde_json::to_vec(link) {
                Ok(bytes) => keywords.insert(Keyword::from(bytes.as_slice())),
                // ignore malformed links (this should never be possible)
                Err(_) => continue,
            };
        }
    }
    keywords
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RedisDbObject {
    #[serde(rename = "o")]
    pub(crate) object: Object,
    #[serde(rename = "t")]
    pub(crate) object_type: ObjectType,
    #[serde(rename = "w")]
    pub(crate) owner: String,
    #[serde(rename = "s")]
    pub(crate) state: StateEnumeration,
    #[serde(rename = "l")]
    pub(crate) tags: HashSet<String>,
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
            keywords.extend(keywords_from_attributes(attributes));
        }
        // index the owner
        keywords.insert(Keyword::from(self.owner.as_bytes()));
        keywords
    }
}

pub const DB_KEY_LENGTH: usize = 32;

pub(crate) struct ObjectsDB {
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

    /// List all the permissions granted to the user
    /// per object uid
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

    /// List all the permissions granted on an object
    /// per user id
    pub async fn list_object_permissions(
        &self,
        uid: &str,
    ) -> KResult<HashMap<String, Vec<ObjectOperationType>>> {
        let wildcard = format!("dp::{}::*", uid);
        let keys: Vec<String> = self.mgr.clone().keys(&wildcard).await?;
        // recover the corresponding permissions
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(&keys).await?;
        keys.into_iter()
            .zip(values)
            .map(|(k, v)| {
                let user_id = k.replace(&wildcard, "");
                let permissions: HashSet<ObjectOperationType> = serde_json::from_slice(&v)?;
                Ok((user_id, permissions.into_iter().collect()))
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

    pub async fn permission_add(
        &self,
        uid: &str,
        user_id: &str,
        permission: ObjectOperationType,
    ) -> KResult<()> {
        #[derive(Clone)]
        struct Context {
            key: String,
            permission: ObjectOperationType,
        }
        let key = ObjectsDB::permissions_key(uid, user_id);
        let ctx = Context {
            key: key.clone(),
            permission,
        };
        transaction_async!(
            self.mgr.clone(),
            &[key.clone()],
            ctx,
            |mut mgr: ConnectionManager, mut pipeline: Pipeline, ctx: Context| async move {
                let old_val: Vec<u8> = mgr.get(&ctx.key).await?;
                let mut current_permissions: HashSet<ObjectOperationType> =
                    serde_json::from_slice(&old_val).map_err(|e| {
                        redis::RedisError::from((
                            ErrorKind::ClientError,
                            "Permissions deserialization error",
                            e.to_string(),
                        ))
                    })?;
                current_permissions.insert(ctx.permission);
                pipeline
                    .set(
                        &ctx.key,
                        serde_json::to_vec(&current_permissions).map_err(|e| {
                            redis::RedisError::from((
                                ErrorKind::ClientError,
                                "Permissions serialization error",
                                e.to_string(),
                            ))
                        })?,
                    )
                    .ignore()
                    .query_async(&mut mgr)
                    .await
            }
        )?;
        Ok(())
    }

    pub async fn permission_remove(
        &self,
        uid: &str,
        user_id: &str,
        permission: ObjectOperationType,
    ) -> KResult<()> {
        #[derive(Clone)]
        struct Context {
            key: String,
            permission: ObjectOperationType,
        }
        let key = ObjectsDB::permissions_key(uid, user_id);
        let ctx = Context {
            key: key.clone(),
            permission,
        };
        transaction_async!(
            self.mgr.clone(),
            &[key.clone()],
            ctx,
            |mut mgr: ConnectionManager, mut pipeline: Pipeline, ctx: Context| async move {
                let old_val: Vec<u8> = mgr.get(&ctx.key).await?;
                let mut current_permissions: HashSet<ObjectOperationType> =
                    serde_json::from_slice(&old_val).map_err(|e| {
                        redis::RedisError::from((
                            ErrorKind::ClientError,
                            "Permissions deserialization error",
                            e.to_string(),
                        ))
                    })?;
                current_permissions.remove(&ctx.permission);
                pipeline
                    .set(
                        &ctx.key,
                        serde_json::to_vec(&current_permissions).map_err(|e| {
                            redis::RedisError::from((
                                ErrorKind::ClientError,
                                "Permissions serialization error",
                                e.to_string(),
                            ))
                        })?,
                    )
                    .ignore()
                    .query_async(&mut mgr)
                    .await
            }
        )?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration};
    use cosmian_kms_utils::{access::ObjectOperationType, crypto::symmetric::create_symmetric_key};
    use redis::aio::ConnectionManager;
    use serial_test::serial;
    use tracing::trace;

    use crate::{
        database::redis::objects_db::{ObjectsDB, RedisDbObject},
        log_utils::log_init,
        result::KResult,
    };

    const REDIS_URL: &str = "redis://localhost:6379";

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

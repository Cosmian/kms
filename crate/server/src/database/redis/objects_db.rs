use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_findex_redis::{FindexError, Keyword, Location, RemovedLocationsFinder};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, StateEnumeration},
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands};
use serde::{Deserialize, Serialize};

use crate::result::KResult;

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
            if bytes.is_empty() {
                continue
            }
            let mut dbo: RedisDbObject = serde_json::from_slice(&bytes)?;
            dbo.object = Object::post_fix(dbo.object_type, dbo.object);
            results.insert(uid.to_string(), dbo);
        }
        Ok(results)
    }

    /// Clear all data
    ///
    /// # Warning
    /// This is definitive
    #[cfg(test)]
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
    use cosmian_kms_utils::crypto::symmetric::create_symmetric_key;
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
}

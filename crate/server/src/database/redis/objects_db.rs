use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, Aes256Gcm, CsRng, Dem, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey,
};
use cloudproof_findex::{
    implementations::redis::{FindexRedisError, RemovedLocationsFinder},
    Keyword, Location,
};
use cosmian_kmip::{
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_types::{Attributes, StateEnumeration},
    },
    KmipResultHelper,
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands};
use serde::{Deserialize, Serialize};

use crate::{error::KmsError, kms_bail, result::KResult};

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

#[derive(Serialize, Deserialize, Clone)]
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
    pub(crate) tags: Option<HashSet<String>>,
    // We use and Option and skip[ serializing for ascending compatibility
    // but there should always be attributes
    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    pub(crate) attributes: Option<Attributes>,
}

impl RedisDbObject {
    pub(crate) const fn new(
        object: Object,
        owner: String,
        state: StateEnumeration,
        tags: Option<HashSet<String>>,
        attributes: Attributes,
    ) -> Self {
        let object_type = object.object_type();
        Self {
            object,
            object_type,
            owner,
            state,
            tags,
            attributes: Some(attributes),
        }
    }

    pub(crate) fn keywords(&self) -> HashSet<Keyword> {
        let mut keywords = self
            .tags
            .as_ref()
            .map(|tags| {
                tags.iter()
                    .map(|tag| Keyword::from(tag.as_bytes()))
                    .collect::<HashSet<Keyword>>()
            })
            .unwrap_or_default();
        // index some of the attributes
        if let Ok(attributes) = self.object.attributes() {
            keywords.extend(keywords_from_attributes(attributes));
        }
        // index the owner
        keywords.insert(Keyword::from(self.owner.as_bytes()));
        keywords
    }
}

pub(crate) const DB_KEY_LENGTH: usize = 32;

pub(crate) struct ObjectsDB {
    mgr: ConnectionManager,
    dem: Aes256Gcm,
    rng: Mutex<CsRng>,
}

impl ObjectsDB {
    pub(crate) fn new(mgr: ConnectionManager, db_key: &SymmetricKey<DB_KEY_LENGTH>) -> Self {
        Self {
            mgr,
            dem: Aes256Gcm::new(db_key),
            rng: Mutex::new(CsRng::from_entropy()),
        }
    }

    fn object_key(uid: &str) -> String {
        format!("do::{uid}")
    }

    fn encrypt_object(&self, uid: &str, redis_db_object: &RedisDbObject) -> KResult<Vec<u8>> {
        let nonce = {
            let mut rng = self.rng.lock().map_err(|e| {
                KmsError::DatabaseError(format!("failed acquiring a lock on the RNG. Error: {e:?}"))
            })?;
            Nonce::new(&mut *rng)
        };
        let ct = self.dem.encrypt(
            &nonce,
            &serde_json::to_vec(redis_db_object)?,
            Some(uid.as_bytes()),
        )?;
        let mut ciphertext = Vec::with_capacity(Aes256Gcm::NONCE_LENGTH + ct.len());
        ciphertext.extend_from_slice(nonce.as_bytes());
        ciphertext.extend(ct);
        Ok(ciphertext)
    }

    fn decrypt_object(&self, uid: &str, ciphertext: &[u8]) -> KResult<RedisDbObject> {
        if ciphertext.len() <= Aes256Gcm::NONCE_LENGTH {
            return Err(KmsError::CryptographicError(
                "invalid ciphertext".to_owned(),
            ))
        }
        let nonce_bytes = &ciphertext[..Aes256Gcm::NONCE_LENGTH];
        let plaintext = self
            .dem
            .decrypt(
                &Nonce::try_from(nonce_bytes)?,
                &ciphertext[Aes256Gcm::NONCE_LENGTH..],
                Some(uid.as_bytes()),
            )
            .with_context(|| format!("decrypt_object uid: {uid}"))?;
        let redis_db_object: RedisDbObject = serde_json::from_slice(&plaintext)
            .with_context(|| format!("decrypt_object uid: {uid}"))?;
        Ok(redis_db_object)
    }

    pub(crate) async fn object_create(
        &self,
        uid: &str,
        redis_db_object: &RedisDbObject,
    ) -> KResult<()> {
        let res: usize = self
            .mgr
            .clone()
            .set_nx(
                Self::object_key(uid),
                self.encrypt_object(uid, redis_db_object)?,
            )
            .await?;
        if res == 1 {
            Ok(())
        } else {
            kms_bail!("object {uid} already exists")
        }
    }

    pub(crate) async fn object_upsert(
        &self,
        uid: &str,
        redis_db_object: &RedisDbObject,
    ) -> KResult<()> {
        self.mgr
            .clone()
            .set::<_, _, ()>(
                Self::object_key(uid),
                self.encrypt_object(uid, redis_db_object)?,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn object_get(&self, uid: &str) -> KResult<Option<RedisDbObject>> {
        let ciphertext: Vec<u8> = self.mgr.clone().get(Self::object_key(uid)).await?;
        if ciphertext.is_empty() {
            return Ok(None)
        }
        let mut dbo: RedisDbObject = self.decrypt_object(uid, &ciphertext)?;
        dbo.object = Object::post_fix(dbo.object_type, dbo.object);
        Ok(Some(dbo))
    }

    #[allow(dead_code)]
    pub(crate) async fn object_delete(&self, uid: &str) -> KResult<()> {
        self.mgr.clone().del::<_, ()>(Self::object_key(uid)).await?;
        Ok(())
    }

    pub(crate) async fn objects_get(
        &self,
        uids: &HashSet<String>,
    ) -> KResult<HashMap<String, RedisDbObject>> {
        let mut pipeline = pipe();
        for uid in uids {
            pipeline.get(Self::object_key(uid));
        }
        let bytes: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;
        let mut results = HashMap::new();
        for (uid, ciphertext) in uids.iter().zip(bytes) {
            if ciphertext.is_empty() {
                continue
            }
            let mut dbo: RedisDbObject = self.decrypt_object(uid, &ciphertext)?;
            dbo.object = Object::post_fix(dbo.object_type, dbo.object);
            results.insert(uid.to_string(), dbo);
        }
        Ok(results)
    }

    pub(crate) async fn atomic(&self, operations: &[RedisOperation]) -> KResult<()> {
        // first check if all created objects do not already exist
        // watching them, will lock them until the end of the transaction
        let mut pipeline = pipe();
        for operation in operations {
            if let RedisOperation::Create(uid, _) = operation {
                let key = Self::object_key(uid);
                pipeline.cmd("WATCH").arg(&key).ignore();
                pipeline.exists(&key);
            }
        }
        let res: Vec<bool> = pipeline.query_async(&mut self.mgr.clone()).await?;
        // if any exists, abort
        if res.iter().any(|exists| *exists) {
            // unwatch all keys
            pipe()
                .cmd("UNWATCH")
                .ignore()
                .query_async::<_, ()>(&mut self.mgr.clone())
                .await?;
            kms_bail!("one or more objects already exist")
        }

        let mut pipeline = pipe();
        pipeline.atomic();
        for operation in operations {
            match operation {
                RedisOperation::Upsert(uid, redis_db_object) => {
                    pipeline.set(
                        Self::object_key(uid),
                        self.encrypt_object(uid, redis_db_object)?,
                    );
                }
                RedisOperation::Delete(uid) => {
                    pipeline.del(Self::object_key(uid));
                }
                RedisOperation::Create(uid, redis_dn_object) => {
                    pipeline.set(
                        Self::object_key(uid),
                        self.encrypt_object(uid, redis_dn_object)?,
                    );
                }
            }
        }
        pipeline.query_async::<_, ()>(&mut self.mgr.clone()).await?;
        Ok(())
    }

    /// Clear all data
    ///
    /// # Warning
    /// This is definitive
    #[cfg(test)]
    pub(crate) async fn clear_all(&self) -> KResult<()> {
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut self.mgr.clone())
            .await?;
        Ok(())
    }
}

#[async_trait]
impl RemovedLocationsFinder for ObjectsDB {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        // Objects and permissions are never removed from the DB
        Ok(HashSet::new())
    }
}

pub(crate) enum RedisOperation {
    Create(String, RedisDbObject),
    Upsert(String, RedisDbObject),
    Delete(String),
}

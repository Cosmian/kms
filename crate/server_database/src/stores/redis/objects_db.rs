use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use cosmian_kmip::{
    KmipResultHelper,
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    Aes256Gcm, CsRng, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
    reexport::rand_core::SeedableRng,
};
use redis::{AsyncCommands, aio::ConnectionManager, pipe};
use serde::{Deserialize, Serialize};

use crate::{
    DbError, db_bail, error::DbResult, migrate_block_cipher_mode_if_needed,
    stores::redis::findex::Keyword,
};

/// Extract the keywords from the attributes
pub(crate) fn keywords_from_attributes(attributes: &Attributes) -> HashSet<Keyword> {
    let mut keywords = HashSet::new();
    // Object Type (e.g., SymmetricKey, SecretData, PublicKey, ...)
    if let Some(object_type) = attributes.object_type {
        keywords.insert(Keyword::from(object_type.to_string().as_bytes()));
    }
    if let Some(algo) = attributes.cryptographic_algorithm {
        keywords.insert(Keyword::from(algo.to_string().as_bytes()));
    }
    if let Some(key_format_type) = attributes.key_format_type {
        keywords.insert(Keyword::from(key_format_type.to_string().as_bytes()));
    }
    if let Some(cryptographic_length) = attributes.cryptographic_length {
        keywords.insert(Keyword::from(cryptographic_length.to_be_bytes().as_slice()));
    }
    // Index the Object Group to support Locate by ObjectGroup
    if let Some(object_group) = &attributes.object_group {
        keywords.insert(Keyword::from(object_group.as_bytes()));
    }
    // Index Application Specific Information as a single structure to allow Locate by it
    if let Some(asi) = &attributes.application_specific_information {
        if let Ok(bytes) = serde_json::to_vec(asi) {
            keywords.insert(Keyword::from(bytes.as_slice()));
        }
    }
    if let Some(links) = &attributes.link {
        for link in links {
            if let Ok(bytes) = serde_json::to_vec(link) {
                keywords.insert(Keyword::from(bytes.as_slice()));
            }
        }
    }
    if let Some(names) = &attributes.name {
        for name in names {
            if let Ok(bytes) = serde_json::to_vec(name) {
                keywords.insert(Keyword::from(bytes.as_slice()));
            }
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
    pub(crate) state: State,
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
        state: State,
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
        // also index the stored Attributes if present (may include ObjectGroup and others)
        if let Some(attributes) = &self.attributes {
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

    fn encrypt_object(&self, uid: &str, redis_db_object: &RedisDbObject) -> DbResult<Vec<u8>> {
        let nonce = {
            let mut rng = self.rng.lock().map_err(|e| {
                DbError::DatabaseError(format!("failed acquiring a lock on the RNG. Error: {e:?}"))
            })?;
            Nonce::new(&mut *rng)
        };
        let ct: Vec<u8> = self.dem.encrypt(
            &nonce,
            &serde_json::to_vec(redis_db_object)?,
            Some(uid.as_bytes()),
        )?;
        let mut ciphertext = Vec::with_capacity(Aes256Gcm::NONCE_LENGTH + ct.len());
        ciphertext.extend_from_slice(nonce.as_bytes());
        ciphertext.extend(ct);
        Ok(ciphertext)
    }

    fn decrypt_object(&self, uid: &str, ciphertext: &[u8]) -> DbResult<RedisDbObject> {
        if ciphertext.len() <= Aes256Gcm::NONCE_LENGTH {
            return Err(DbError::CryptographicError("invalid ciphertext".to_owned()));
        }
        let nonce_bytes = &ciphertext.get(..Aes256Gcm::NONCE_LENGTH).ok_or_else(|| {
            DbError::ServerError("decrypt_object: indexing slicing failed for nonce".to_owned())
        })?;
        let plaintext = self
            .dem
            .decrypt(
                &Nonce::try_from(*nonce_bytes)?,
                ciphertext.get(Aes256Gcm::NONCE_LENGTH..).ok_or_else(|| {
                    DbError::CryptographicError(
                        "decrypt_object: indexing slicing failed for plaintext".to_owned(),
                    )
                })?,
                Some(uid.as_bytes()),
            )
            .with_context(|| format!("decrypt_object uid: {uid}"))?;
        // Mutability below is needed to Migrate legacy BlockCipherMode in-place - otherwise we should destructure and that's very verbose.
        let mut redis_db_object: RedisDbObject = serde_json::from_slice(&plaintext)
            .with_context(|| format!("decrypt_object uid: {uid}"))?;
        redis_db_object.object = migrate_block_cipher_mode_if_needed(redis_db_object.object);
        Ok(redis_db_object)
    }

    pub(crate) async fn object_create(
        &self,
        uid: &str,
        redis_db_object: &RedisDbObject,
    ) -> DbResult<()> {
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
            db_bail!("object {uid} already exists")
        }
    }

    pub(crate) async fn object_upsert(
        &self,
        uid: &str,
        redis_db_object: &RedisDbObject,
    ) -> DbResult<()> {
        self.mgr
            .clone()
            .set::<_, _, ()>(
                Self::object_key(uid),
                self.encrypt_object(uid, redis_db_object)?,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn object_get(&self, uid: &str) -> DbResult<Option<RedisDbObject>> {
        let ciphertext: Vec<u8> = self.mgr.clone().get(Self::object_key(uid)).await?;
        if ciphertext.is_empty() {
            return Ok(None);
        }
        let dbo: RedisDbObject = self.decrypt_object(uid, &ciphertext)?;
        Ok(Some(dbo))
    }

    pub(crate) async fn object_delete(&self, uid: &str) -> DbResult<()> {
        self.mgr.clone().del::<_, ()>(Self::object_key(uid)).await?;
        Ok(())
    }

    pub(crate) async fn objects_get(
        &self,
        uids: &HashSet<String>,
    ) -> DbResult<HashMap<String, RedisDbObject>> {
        let mut pipeline = pipe();
        for uid in uids {
            pipeline.get(Self::object_key(uid));
        }
        let bytes: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;
        let mut results = HashMap::new();
        for (uid, ciphertext) in uids.iter().zip(bytes) {
            if ciphertext.is_empty() {
                continue;
            }
            let dbo: RedisDbObject = self.decrypt_object(uid, &ciphertext)?;
            results.insert(uid.clone(), dbo);
        }
        Ok(results)
    }

    pub(crate) async fn atomic(&self, operations: &[RedisOperation]) -> DbResult<Vec<String>> {
        // first check if all created objects do not already exist, watching them
        // will lock them until the end of the transaction
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
                .query_async::<()>(&mut self.mgr.clone())
                .await?;
            db_bail!("one or more objects already exist")
        }

        let mut res = Vec::with_capacity(operations.len());
        let mut pipeline = pipe();
        pipeline.atomic();
        for operation in operations {
            match operation {
                RedisOperation::Upsert(uid, redis_db_object) => {
                    pipeline.set(
                        Self::object_key(uid),
                        self.encrypt_object(uid, redis_db_object)?,
                    );
                    res.push(uid.clone());
                }
                RedisOperation::Delete(uid) => {
                    pipeline.del(Self::object_key(uid));
                    res.push(uid.clone());
                }
                RedisOperation::Create(uid, redis_dn_object) => {
                    pipeline.set(
                        Self::object_key(uid),
                        self.encrypt_object(uid, redis_dn_object)?,
                    );
                    res.push(uid.clone());
                }
            }
        }
        pipeline.query_async::<()>(&mut self.mgr.clone()).await?;
        Ok(res)
    }
}

pub(crate) enum RedisOperation {
    Create(String, RedisDbObject),
    Upsert(String, RedisDbObject),
    Delete(String),
}

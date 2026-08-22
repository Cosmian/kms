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
use cosmian_logger::debug;
use redis::{AsyncCommands, aio::ConnectionManager, pipe};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
    // Index rotate_name so find_by_rotate_name can search by keyword
    if let Some(rotate_name) = &attributes.rotate_name {
        keywords.insert(Keyword::from(
            format!("rotate_name::{rotate_name}").as_bytes(),
        ));
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
        // index the wrapping key UID so find_wrapped_by can search by keyword
        if let Some(wk_uid) = self.object.wrapping_key_uid() {
            keywords.insert(Keyword::from(format!("wrapped_by::{wk_uid}").as_bytes()));
        }
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
        // For Create operations, use SET_NX (set-if-not-exists) to atomically
        // check-and-set without WATCH.  WATCH + MULTI/EXEC is unsafe with a
        // shared ConnectionManager: any concurrent write on the same connection
        // between WATCH and EXEC aborts the transaction silently.
        //
        // For Upsert/Delete, a plain SET/DEL pipeline suffices (idempotent).

        let mut res = Vec::with_capacity(operations.len());
        let mut pipeline = pipe();

        for operation in operations {
            match operation {
                RedisOperation::Create(uid, redis_db_object) => {
                    // SET key value NX — fails if key already exists
                    pipeline
                        .cmd("SET")
                        .arg(Self::object_key(uid))
                        .arg(self.encrypt_object(uid, redis_db_object)?)
                        .arg("NX");
                    res.push(uid.clone());
                }
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
            }
        }

        // Execute the pipeline.  For SET ... NX commands, Redis returns nil when
        // the key already exists.  We parse as Vec<Value> to detect failures.
        let results: Vec<redis::Value> = pipeline.query_async(&mut self.mgr.clone()).await?;

        // Verify that Create operations succeeded (non-nil response)
        for (result_idx, operation) in operations.iter().enumerate() {
            if let RedisOperation::Create(uid, _) = operation {
                if matches!(results.get(result_idx), Some(redis::Value::Nil)) {
                    db_bail!("object {uid} already exists");
                }
            }
        }

        Ok(res)
    }
}

pub(crate) enum RedisOperation {
    Create(String, RedisDbObject),
    Upsert(String, RedisDbObject),
    Delete(String),
}

// ── Live-object counter key ──────────────────────────────────────────────────
//
// A single Redis key `kms::metrics::live_object_count` holds the number of
// objects that are NOT in a terminal (Destroyed / Destroyed_Compromised) state.
//
// Reads  → one `GET`  — O(1), no decryption.
// Writes → one `INCRBY delta` piggybacked on every mutating operation.
// Bootstrap → first call when the key is absent runs a one-time SCAN+decrypt to
//             set the initial value; all subsequent calls are O(1).
//
// The counter lives next to the `ObjectsDB` implementation because:
//  - it uses the same `ConnectionManager` and the same `do::*` key namespace;
//  - the bootstrap scan reuses `decrypt_object`, which requires `&self`;
//  - keeping it here avoids threading the counter through the higher-level
//    `RedisWithFindex` layer with extra `Arc` indirection.

/// Redis key that stores the count of live (non-destroyed) objects.
pub(crate) const LIVE_COUNT_KEY: &str = "kms::metrics::live_object_count";

/// Redis key that stores the count of non-destroyed key objects
/// (`SymmetricKey`, `PrivateKey`, `PublicKey`, `SplitKey`).
pub(crate) const ACTIVE_KEY_COUNT_KEY: &str = "kms::metrics::active_key_count";

/// SCAN batch hint passed to Redis.  Redis may return more or fewer keys per
/// batch; `200` is a pragmatic balance between round-trips and command latency.
const SCAN_BATCH_HINT: u64 = 200;

impl ObjectsDB {
    /// Atomically adjust the live-object counter by `delta`.
    ///
    /// Uses `INCRBY` (positive) or `DECRBY` (negative). Redis creates the key
    /// with value `0` before applying the increment if it does not exist, so
    /// calling this before the bootstrap is safe — the counter will start from
    /// `delta` rather than the true absolute count.  The cron-driven
    /// `count_all_non_destroyed` will correct the value on its next tick.
    pub(crate) async fn adjust_live_count(&self, delta: i64) -> DbResult<()> {
        if delta == 0 {
            return Ok(());
        }
        self.mgr
            .clone()
            .incr::<_, i64, i64>(LIVE_COUNT_KEY, delta)
            .await?;
        Ok(())
    }

    /// Return the current live-object count, or `None` if the key has never
    /// been set (i.e. the server has not yet bootstrapped the counter).
    pub(crate) async fn get_live_count(&self) -> DbResult<Option<u64>> {
        let raw: Option<i64> = self.mgr.clone().get(LIVE_COUNT_KEY).await?;
        Ok(raw.map(|n| u64::try_from(n.max(0)).unwrap_or(0)))
    }

    /// Overwrite the live-object counter with an absolute value.
    ///
    /// Called once during bootstrap (when `get_live_count` returns `None`) and
    /// **never** again during normal operation.
    pub(crate) async fn set_live_count(&self, count: u64) -> DbResult<()> {
        self.mgr
            .clone()
            .set::<_, _, ()>(LIVE_COUNT_KEY, count)
            .await?;
        Ok(())
    }

    /// One-time bootstrap: scan every `do::*` key, decrypt each blob, and count
    /// objects whose `state` is not `Destroyed` or `Destroyed_Compromised`.
    ///
    /// This is O(N) over the keyspace and decrypts every object — it is
    /// expensive by design and must only be called once (when the counter key is
    /// absent).  After this call the incremental counter path takes over.
    /// Scan every `do::*` key and return (uid, `[``RedisDbObject``]`) pairs for all objects.
    ///
    /// Corrupt or foreign blobs are skipped with a `debug!` log.
    pub(crate) async fn scan_all_objects(&self) -> DbResult<Vec<(String, RedisDbObject)>> {
        let mut results = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(SCAN_BATCH_HINT)
                .query_async(&mut self.mgr.clone())
                .await?;

            if !keys.is_empty() {
                let mut pipeline = pipe();
                for key in &keys {
                    pipeline.get(key);
                }
                let values: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;

                for (key, ciphertext) in keys.iter().zip(values) {
                    if ciphertext.is_empty() {
                        continue;
                    }
                    let uid = key.strip_prefix("do::").unwrap_or(key.as_str());
                    match self.decrypt_object(uid, &ciphertext) {
                        Ok(obj) => results.push((uid.to_owned(), obj)),
                        Err(e) => {
                            debug!("[redis-scan-all] skipping key {key}: {e}");
                        }
                    }
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(results)
    }

    /// # Decryption errors
    ///
    /// A single corrupt or foreign blob does not abort the scan: it is skipped
    /// with a `debug!` log.  The 30-second cron sync will re-run bootstrap if
    /// the counter key is ever lost (e.g. after `FLUSHDB` in tests).
    pub(crate) async fn scan_count_non_destroyed(&self) -> DbResult<u64> {
        let mut count: u64 = 0;
        let mut cursor: u64 = 0;
        loop {
            // SCAN cursor MATCH do::* COUNT hint
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(SCAN_BATCH_HINT)
                .query_async(&mut self.mgr.clone())
                .await?;

            if !keys.is_empty() {
                // Pipeline-GET all values in this batch (one round-trip).
                let mut pipeline = pipe();
                for key in &keys {
                    pipeline.get(key);
                }
                let values: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;

                for (key, ciphertext) in keys.iter().zip(values) {
                    if ciphertext.is_empty() {
                        // Key disappeared between SCAN and GET — harmless.
                        continue;
                    }
                    // Strip the "do::" prefix to recover the raw UID used as
                    // AEAD additional data during encryption.
                    let uid = key.strip_prefix("do::").unwrap_or(key.as_str());
                    match self.decrypt_object(uid, &ciphertext) {
                        Ok(obj) => {
                            if !matches!(obj.state, State::Destroyed | State::Destroyed_Compromised)
                            {
                                count += 1;
                            }
                        }
                        Err(e) => {
                            // Skip corrupted / foreign blobs rather than
                            // aborting the entire count.
                            debug!("[redis-bootstrap] skipping key {key}: {e}");
                        }
                    }
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(count)
    }

    /// Atomically adjust the active-key counter by `delta`.
    ///
    /// "Active key" means a non-destroyed key object (`ObjectType` ∈ {`SymmetricKey`,
    /// `PrivateKey`, `PublicKey`, `SplitKey`}, state ∉ {`Destroyed`, `Destroyed_Compromised`}).
    /// Uses `INCRBY`; the key is auto-created at `delta` if absent — the cron
    /// reconcile will correct it on the next tick.
    pub(crate) async fn adjust_active_key_count(&self, delta: i64) -> DbResult<()> {
        if delta == 0 {
            return Ok(());
        }
        self.mgr
            .clone()
            .incr::<_, i64, i64>(ACTIVE_KEY_COUNT_KEY, delta)
            .await?;
        Ok(())
    }

    /// Return the current active-key count, or `None` if the key has never
    /// been set (i.e. the bootstrap scan has not yet run).
    pub(crate) async fn get_active_key_count(&self) -> DbResult<Option<u64>> {
        let raw: Option<i64> = self.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
        Ok(raw.map(|n| u64::try_from(n.max(0)).unwrap_or(0)))
    }

    /// Overwrite the active-key counter with an absolute value.
    ///
    /// Called once during bootstrap and by the reconcile path.
    pub(crate) async fn set_active_key_count(&self, count: u64) -> DbResult<()> {
        self.mgr
            .clone()
            .set::<_, _, ()>(ACTIVE_KEY_COUNT_KEY, count)
            .await?;
        Ok(())
    }

    /// One-time bootstrap: scan every `do::*` key, decrypt each blob, and count
    /// objects that are both a key type (`SymmetricKey`, `PrivateKey`, `PublicKey`,
    /// `SplitKey`) **and** non-destroyed.
    ///
    /// Same cost and error-handling semantics as `scan_count_non_destroyed`.
    pub(crate) async fn scan_count_non_destroyed_keys(&self) -> DbResult<u64> {
        let mut count: u64 = 0;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(SCAN_BATCH_HINT)
                .query_async(&mut self.mgr.clone())
                .await?;

            if !keys.is_empty() {
                let mut pipeline = pipe();
                for key in &keys {
                    pipeline.get(key);
                }
                let values: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;

                for (key, ciphertext) in keys.iter().zip(values) {
                    if ciphertext.is_empty() {
                        continue;
                    }
                    let uid = key.strip_prefix("do::").unwrap_or(key.as_str());
                    match self.decrypt_object(uid, &ciphertext) {
                        Ok(obj) => {
                            let is_key = matches!(
                                obj.object_type,
                                ObjectType::SymmetricKey
                                    | ObjectType::PrivateKey
                                    | ObjectType::PublicKey
                                    | ObjectType::SplitKey
                            );
                            let is_non_destroyed = !matches!(
                                obj.state,
                                State::Destroyed | State::Destroyed_Compromised
                            );
                            if is_key && is_non_destroyed {
                                count += 1;
                            }
                        }
                        Err(e) => {
                            debug!("[redis-bootstrap] skipping key {key}: {e}");
                        }
                    }
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(count)
    }

    /// Scan all `do::*` keys and return `(uid, owner)` pairs for every `Active`
    /// object that has `rotate_automatic = true` and whose next rotation instant
    /// is ≤ `now`.
    ///
    /// This is an O(N) scan used by the auto-rotation scheduler (cron job),
    /// whose low invocation frequency makes the cost acceptable.  The method
    /// mirrors the pattern of [`Self::scan_count_non_destroyed`] but collects
    /// results instead of counting.
    pub(crate) async fn scan_due_for_rotation(
        &self,
        now: OffsetDateTime,
    ) -> DbResult<Vec<(String, String)>> {
        let mut due: Vec<(String, String)> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(SCAN_BATCH_HINT)
                .query_async(&mut self.mgr.clone())
                .await?;

            if !keys.is_empty() {
                let mut pipeline = pipe();
                for key in &keys {
                    pipeline.get(key);
                }
                let values: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;

                for (key, ciphertext) in keys.iter().zip(values) {
                    if ciphertext.is_empty() {
                        continue;
                    }
                    let uid = key.strip_prefix("do::").unwrap_or(key.as_str());
                    match self.decrypt_object(uid, &ciphertext) {
                        Ok(obj) => {
                            if obj.state != State::Active {
                                continue;
                            }
                            let Some(ref attrs) = obj.attributes else {
                                continue;
                            };
                            if attrs.rotate_automatic != Some(true) {
                                continue;
                            }
                            if crate::stores::sql::locate_query::is_due_for_rotation(attrs, now) {
                                due.push((uid.to_owned(), obj.owner.clone()));
                            }
                        }
                        Err(e) => {
                            debug!("[redis-scan-rotation] skipping key {key}: {e}");
                        }
                    }
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(due)
    }

    /// Scan all `do::*` keys and return `(uid, wrapping_key_uid)` pairs for every
    /// object that embeds a wrapping key (i.e. `Object::wrapping_key_uid()` is
    /// `Some`).
    ///
    /// Used once at startup to backfill the `wrapped_by::<uid>` Findex index for
    /// objects created before that index existed (see
    /// [`crate::stores::RedisWithFindex::instantiate`]). Mirrors the scan pattern
    /// of [`Self::scan_due_for_rotation`].
    pub(crate) async fn scan_wrapped_objects(&self) -> DbResult<Vec<(String, String)>> {
        let mut wrapped: Vec<(String, String)> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(SCAN_BATCH_HINT)
                .query_async(&mut self.mgr.clone())
                .await?;

            if !keys.is_empty() {
                let mut pipeline = pipe();
                for key in &keys {
                    pipeline.get(key);
                }
                let values: Vec<Vec<u8>> = pipeline.query_async(&mut self.mgr.clone()).await?;

                for (key, ciphertext) in keys.iter().zip(values) {
                    if ciphertext.is_empty() {
                        continue;
                    }
                    let uid = key.strip_prefix("do::").unwrap_or(key.as_str());
                    match self.decrypt_object(uid, &ciphertext) {
                        Ok(obj) => {
                            if let Some(wk_uid) = obj.object.wrapping_key_uid() {
                                wrapped.push((uid.to_owned(), wk_uid));
                            }
                        }
                        Err(e) => {
                            debug!("[redis-scan-wrapped] skipping key {key}: {e}");
                        }
                    }
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(wrapped)
    }
}

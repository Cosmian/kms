use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::Arc,
};

use async_trait::async_trait;
use cosmian_findex::{Findex, IndexADT, MemoryEncryptionLayer, generic_decode, generic_encode};
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
    },
};
use cosmian_kms_crypto::{
    crypto::password_derivation::derive_key_from_password,
    reexport::cosmian_crypto_core::{FixedSizeCBytes, Secret, SymmetricKey, kdf256},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore, UserId,
};
use cosmian_logger::{debug, error, trace};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, RedisMemory};
use redis::aio::ConnectionManager;
use uuid::Uuid;

use super::{
    FINDEX_KEY_LENGTH,
    objects_db::{
        ACTIVE_KEY_COUNT_KEY, DB_KEY_LENGTH, LIVE_COUNT_KEY, ObjectsDB, RedisDbObject,
        keywords_from_attributes,
    },
    permissions::PermissionDB,
};
use crate::{
    db_bail, db_error,
    error::{DbError, DbResult},
    stores::{
        REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
        migrate::{DbState, Migrate, WRAPPING_KEY_BACKFILL_PARAM},
        redis::{
            findex::{CUSTOM_WORD_LENGTH, FindexRedis, IndexedValue, Keyword},
            objects_db::{AtomicScriptOutcome, ScriptOp},
            permissions::{FindexUserId, ObjectUid},
        },
    },
};

const REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT: &[u8; 16] = b"rediswithfindex_";
const REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT: &[u8; 2] = b"db";

/// Returns `true` when an object's state counts toward the live-object total.
///
/// `Destroyed` and `Destroyed_Compromised` are terminal states — the object is
/// no longer usable and should not appear in the `kms.objects.total` gauge.
#[inline]
const fn is_live(state: State) -> bool {
    !matches!(state, State::Destroyed | State::Destroyed_Compromised)
}

/// Returns `true` when `object_type` is a key type counted by `kms.keys.active.count`.
///
/// Key types: `SymmetricKey`, `PrivateKey`, `PublicKey`, `SplitKey`.
/// Excluded: `Certificate`, `SecretData`, `OpaqueObject`, `PGPKey`, `CertificateRequest`.
#[inline]
const fn is_key_type(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::SymmetricKey
            | ObjectType::PrivateKey
            | ObjectType::PublicKey
            | ObjectType::SplitKey
    )
}

/// Derive a Redis Master Key from a password
pub fn redis_master_key_from_password(
    master_password: &str,
) -> DbResult<SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>> {
    let output_key_material = derive_key_from_password::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>(
        REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT,
        master_password.as_bytes(),
    )?;

    let master_secret_key: SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH> =
        SymmetricKey::try_from_slice(&output_key_material)?;

    Ok(master_secret_key)
}

fn intersect_all_refs<'a>(sets: &'a Vec<HashSet<&'a IndexedValue>>) -> HashSet<&'a IndexedValue> {
    sets.iter()
        .cloned()
        .reduce(|acc, set| acc.intersection(&set).copied().collect())
        .unwrap_or_else(HashSet::new)
}

pub(crate) async fn init_findex_redis(
    findex_key: &Secret<FINDEX_KEY_LENGTH>,
    redis_url: &str,
) -> DbResult<FindexRedis> {
    let redis_memory =
        RedisMemory::<Address<ADDRESS_LENGTH>, [u8; CUSTOM_WORD_LENGTH]>::new_with_url(redis_url)
            .await?;

    let encrypted_redis_memory = MemoryEncryptionLayer::new(findex_key, redis_memory);

    Ok(Findex::new(
        encrypted_redis_memory,
        generic_encode,
        generic_decode,
    ))
}

#[derive(Clone)]
pub(crate) struct RedisWithFindex {
    pub(crate) mgr: ConnectionManager,
    objects_db: Arc<ObjectsDB>,
    permission_db: PermissionDB,
    findex: Arc<FindexRedis>,
    /// 32-byte key used to derive per-user obfuscated ceremony Redis key names.
    ceremony_derivation_key: [u8; 32],
    /// Obfuscated Redis SET key tracking the set of currently-active CO usernames.
    /// Used for efficient `is_any_crypto_officer_activated` without scanning all keys.
    ceremony_active_cos_key: String,
}

/// How a `UidState`'s physical write must be guarded.
enum Precondition {
    /// Key must not already exist (`AtomicOperation::Create`).
    Create,
    /// Key must still equal the raw bytes read into `baseline_raw` when this
    /// uid was first touched in the current attempt.
    Cas,
}

/// Accumulated state for one uid across every `AtomicOperation` in a batch
/// that touches it, within a single attempt of `RedisWithFindex::try_atomic`.
struct UidState {
    precondition: Precondition,
    /// Raw ciphertext read at first touch (`None` = uid was absent). Used as
    /// the CAS baseline; irrelevant for `Precondition::Create`.
    baseline_raw: Option<Vec<u8>>,
    /// Decoded baseline — used for Findex keyword diffing.
    baseline: Option<RedisDbObject>,
    /// Working value after the operations applied so far. `None` means the
    /// uid is absent / deleted when the attempt commits.
    current: Option<RedisDbObject>,
}

/// Outcome of one `try_atomic` attempt.
enum AtomicAttempt {
    Committed(Vec<String>),
    /// A `Cas` precondition lost a race with a concurrent writer; retry the
    /// whole attempt with fresh baselines.
    Retry,
}

/// Keyword-index change for one uid: `(uid, old keywords, new keywords)`;
/// `None` new keywords means the object is deleted.
type IndexDiff<'a> = (&'a str, HashSet<Keyword>, Option<HashSet<Keyword>>);

/// Upper bound on whole-batch retries after lost CAS races.
const MAX_ATOMIC_CAS_ATTEMPTS: u32 = 64;

/// `true` if the stored object carries every tag in `tags`. Used to discard
/// stale Findex hits (the index is written after the object, see `try_atomic`).
fn has_all_tags(object: &RedisDbObject, tags: &HashSet<String>) -> bool {
    tags.iter().all(|tag| {
        object
            .tags
            .as_ref()
            .is_some_and(|stored| stored.contains(tag))
    })
}

impl RedisWithFindex {
    pub(crate) async fn instantiate(
        redis_url: &str,
        master_key: Secret<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        clear_database: bool,
    ) -> DbResult<Self> {
        // derive a DB Key
        let mut db_key = SymmetricKey::<DB_KEY_LENGTH>::default();
        kdf256!(
            &mut *db_key,
            REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT,
            &*master_key
        );

        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;

        let objects_db = Arc::new(ObjectsDB::new(mgr.clone(), &db_key));

        // there is no mistake in passing the master key to findex - the kdf key derivation is performed upon the creation of the encryption layer (method `new` line 53)
        let findex = Arc::new(init_findex_redis(&master_key, redis_url).await?);

        let permission_db = PermissionDB::new(findex.clone());

        if clear_database {
            redis::cmd("FLUSHDB")
                .query_async::<()>(&mut mgr.clone())
                .await?;
        }

        let count: usize = redis::cmd("DBSIZE")
            .query_async(&mut mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get Redis DB size: {e}")))?;
        trace!("Redis DB size: {count}");

        // Derive ceremony key material from the master key.
        // Per-user ceremony record keys are computed at call time using this derivation key.
        // The `ceremony_active_cos_key` is a SET key that tracks active CO usernames.
        let mut ceremony_derivation_key = [0_u8; 32];
        kdf256!(
            &mut ceremony_derivation_key,
            &*master_key,
            b"ceremony_key_derivation"
        );
        let ceremony_active_cos_key =
            Self::derive_ceremony_key_name(&master_key, b"active_cos_set");
        let redis_with_findex = Self {
            mgr,
            objects_db,
            permission_db,
            findex,
            ceremony_derivation_key,
            ceremony_active_cos_key,
        };

        if count == 0 {
            debug!("Empty Redis database detected. Initializing a new database instance.");
            redis_with_findex
                .set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            redis_with_findex.set_db_state(DbState::Ready).await?;
        } else {
            // Existing database detected. Accept databases that have our version/state markers;
            // refuse truly legacy databases (no markers or non-ready state) since migrations were removed.
            let db_version = redis_with_findex.get_current_db_version().await?;
            let db_state = redis_with_findex.get_db_state().await?;

            match (db_version, db_state) {
                (Some(version), Some(DbState::Ready)) => {
                    debug!(
                        "Existing Redis database detected (version {version}). Using current database."
                    );
                    // proceed without reinitialization
                }
                _ => {
                    return Err(DbError::DatabaseError(
                        "Legacy Redis/Findex migration support has been removed. \
                        Please export your data from the legacy KMS and reimport into the current version."
                            .to_owned(),
                    ));
                }
            }
        }

        // One-time backfill of the `wrapped_by::<uid>` Findex index for objects
        // created before that index existed. Gated by a completion marker so the
        // O(N) scan runs at most once per database (a fresh database has no
        // objects, so this is a no-op that only writes the marker).
        redis_with_findex.backfill_wrapped_by_index().await?;

        Ok(redis_with_findex)
    }

    /// Backfill the `wrapped_by::<uid>` Findex index for wrapped objects that
    /// predate that index.
    ///
    /// `find_wrapped_by` (used by key rotation) relies on a `wrapped_by::<uid>`
    /// keyword that newer code writes at insert time. Objects stored by earlier
    /// versions lack it, so they would be invisible to rotation. This method
    /// scans every object once, (re-)inserts the keyword for wrapped ones, and
    /// records a `wrapping_key_id_backfilled` marker so the scan never re-runs.
    /// Re-inserting an already-indexed keyword is idempotent.
    pub(crate) async fn backfill_wrapped_by_index(&self) -> DbResult<()> {
        let marker: Option<String> = redis::cmd("GET")
            .arg(WRAPPING_KEY_BACKFILL_PARAM)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to read wrapped_by backfill marker: {e}"))
            })?;
        if marker.as_deref() == Some("true") {
            return Ok(());
        }

        let wrapped = self.objects_db.scan_wrapped_objects().await?;
        for (uid, wrapping_key_uid) in wrapped {
            let keyword = Keyword::from(format!("wrapped_by::{wrapping_key_uid}").as_bytes());
            let indexed_uid = IndexedValue::from(uid.as_bytes());
            self.findex.insert(keyword, [indexed_uid]).await?;
        }

        redis::cmd("SET")
            .arg(WRAPPING_KEY_BACKFILL_PARAM)
            .arg("true")
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to set wrapped_by backfill marker: {e}"))
            })?;
        Ok(())
    }

    /// Test-only accessor to the underlying object store, used to seed a legacy
    /// (unindexed) object when exercising [`Self::backfill_wrapped_by_index`].
    #[cfg(test)]
    pub(crate) fn objects_db(&self) -> &ObjectsDB {
        &self.objects_db
    }

    /// Return the working state of `uid` within this attempt, reading and
    /// recording its baseline from Redis on first touch.
    async fn touch<'a>(
        &self,
        states: &'a mut HashMap<String, UidState>,
        uid: &str,
    ) -> DbResult<&'a mut UidState> {
        let state = match states.entry(uid.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let baseline_raw = self.objects_db.object_get_raw(uid).await?;
                let baseline = baseline_raw
                    .as_deref()
                    .map(|raw| self.objects_db.decrypt_object(uid, raw))
                    .transpose()?;
                entry.insert(UidState {
                    precondition: Precondition::Cas,
                    baseline_raw,
                    current: baseline.clone(),
                    baseline,
                })
            }
        };
        Ok(state)
    }

    /// One attempt at applying `operations` atomically. Returns `Retry` on a
    /// lost CAS race; any other error (including a `Create` conflict) is
    /// returned directly and must not be retried by the caller.
    ///
    /// Findex keywords and counters are only written after the physical Redis
    /// write is confirmed, so a failed batch leaves no trace.
    async fn try_atomic(
        &self,
        user: &UserId,
        operations: &[AtomicOperation],
    ) -> DbResult<AtomicAttempt> {
        // Multiple operations on the same uid within the batch build on each
        // other (e.g. UpdateObject then UpdateState) through `UidState::current`.
        let mut states: HashMap<String, UidState> = HashMap::new();
        let mut live_delta: i64 = 0;
        let mut active_key_delta: i64 = 0;

        for operation in operations {
            match operation {
                AtomicOperation::Create((uid, _owner, object, attributes, tags)) => {
                    let db_object = RedisDbObject::new(
                        object.clone(),
                        user.as_str().to_owned(),
                        attributes.state.unwrap_or(State::PreActive),
                        Some(tags.clone()),
                        attributes.clone(),
                    );
                    // New objects are always live.
                    live_delta += 1;
                    if is_key_type(db_object.object_type) {
                        active_key_delta += 1;
                    }
                    match states.get_mut(uid) {
                        // Earlier operation in this batch already touched the uid:
                        // Create is only valid if that left it absent (e.g. Delete
                        // then Create); the earlier precondition is kept.
                        Some(entry) if entry.current.is_some() => {
                            db_bail!("object {uid} already exists")
                        }
                        Some(entry) => entry.current = Some(db_object),
                        None => {
                            states.insert(
                                uid.clone(),
                                UidState {
                                    precondition: Precondition::Create,
                                    baseline_raw: None,
                                    baseline: None,
                                    current: Some(db_object),
                                },
                            );
                        }
                    }
                }
                AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                    let entry = self.touch(&mut states, uid).await?;
                    let old_obj = entry.current.take();
                    if let Some(old) = &old_obj {
                        if old.owner != user.as_str() {
                            return Err(DbError::Unauthorized(format!(
                                "User '{user}' does not own object '{uid}' and cannot overwrite it"
                            )));
                        }
                    }
                    let old_state = old_obj.as_ref().map(|o| o.state);
                    let old_object_type = old_obj.as_ref().map(|o| o.object_type);
                    // `None` tags = keep the current ones (read from the same
                    // baseline the CAS guards, so a concurrent change retries).
                    let final_tags = tags.clone().unwrap_or_else(|| {
                        old_obj
                            .as_ref()
                            .and_then(|o| o.tags.clone())
                            .unwrap_or_default()
                    });
                    let db_object = RedisDbObject::new(
                        object.clone(),
                        user.as_str().to_owned(),
                        *state,
                        Some(final_tags),
                        attributes.clone(),
                    );
                    let new_live = i64::from(is_live(*state));
                    live_delta +=
                        old_state.map_or(new_live, |old| new_live - i64::from(is_live(old)));
                    if is_key_type(db_object.object_type) {
                        let old_key_live = old_object_type
                            .filter(|ot| is_key_type(*ot))
                            .and(old_state)
                            .map_or(0, |old| i64::from(is_live(old)));
                        active_key_delta += new_live - old_key_live;
                    }
                    entry.current = Some(db_object);
                }
                AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                    // State is unchanged by UpdateObject — no counter adjustment.
                    let entry = self.touch(&mut states, uid).await?;
                    let Some(db_object) = entry.current.as_mut() else {
                        return Err(DbError::ItemNotFound(uid.clone()));
                    };
                    db_object.object = object.clone();
                    if tags.is_some() {
                        db_object.tags.clone_from(tags);
                    }
                    db_object.attributes = Some(attributes.clone());
                }
                AtomicOperation::UpdateState((uid, state)) => {
                    let entry = self.touch(&mut states, uid).await?;
                    let Some(db_object) = entry.current.as_mut() else {
                        return Err(DbError::ItemNotFound(uid.clone()));
                    };
                    let old_live = i64::from(is_live(db_object.state));
                    let new_live = i64::from(is_live(*state));
                    db_object.state = *state;
                    live_delta += new_live - old_live;
                    if is_key_type(db_object.object_type) {
                        active_key_delta += new_live - old_live;
                    }
                }
                AtomicOperation::Delete(uid) => {
                    let entry = self.touch(&mut states, uid).await?;
                    if let Some(old) = entry.current.take() {
                        if is_live(old.state) {
                            live_delta -= 1;
                            if is_key_type(old.object_type) {
                                active_key_delta -= 1;
                            }
                        }
                    }
                }
            }
        }

        let mut script_ops = Vec::with_capacity(states.len());
        let mut index_diffs: Vec<IndexDiff<'_>> = Vec::with_capacity(states.len());
        for (uid, state) in &states {
            let old_keywords = state
                .baseline
                .as_ref()
                .map(RedisDbObject::keywords)
                .unwrap_or_default();
            if let Some(value) = &state.current {
                script_ops.push(match state.precondition {
                    Precondition::Create => ScriptOp::Create {
                        uid: uid.clone(),
                        value: value.clone(),
                    },
                    Precondition::Cas => ScriptOp::Cas {
                        uid: uid.clone(),
                        expected: state.baseline_raw.clone(),
                        value: value.clone(),
                    },
                });
                index_diffs.push((uid, old_keywords, Some(value.keywords())));
            } else {
                script_ops.push(ScriptOp::Delete {
                    uid: uid.clone(),
                    expected: state.baseline_raw.clone(),
                });
                index_diffs.push((uid, old_keywords, None));
            }
        }

        match self.objects_db.atomic_script(&script_ops).await? {
            AtomicScriptOutcome::CreateConflict(uid) => db_bail!("object {uid} already exists"),
            AtomicScriptOutcome::CasConflict => Ok(AtomicAttempt::Retry),
            AtomicScriptOutcome::Committed => {
                // The object writes are committed: a failure past this point leaves
                // the Findex index and/or counters behind, so say which uids.
                let post_commit = async {
                    for (uid, old_keywords, new_keywords) in index_diffs {
                        match new_keywords {
                            Some(new_keywords) => {
                                self.update_findex_keywords(uid, &old_keywords, &new_keywords)
                                    .await?;
                            }
                            None => self.delete_findex_keywords(uid, &old_keywords).await?,
                        }
                    }
                    self.objects_db.adjust_live_count(live_delta).await?;
                    self.objects_db
                        .adjust_active_key_count(active_key_delta)
                        .await
                };
                let uids: Vec<String> = operations
                    .iter()
                    .map(|op| op.get_object_uid().to_owned())
                    .collect();
                if let Err(e) = post_commit.await {
                    error!(
                        "atomic: objects {uids:?} were committed but the Findex index or counters \
                         could not be updated (index/counters need repair): {e}"
                    );
                    return Err(e);
                }
                Ok(AtomicAttempt::Committed(uids))
            }
        }
    }

    /// Prepare a brand-new object for insertion and eagerly write its Findex
    /// keywords. Used only by the standalone `create()` trait method — `Create`
    /// inside `atomic()` builds the `RedisDbObject` directly so its Findex
    /// writes are deferred until the physical write is confirmed.
    async fn prepare_object_for_create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> DbResult<(String, RedisDbObject)> {
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let db_object = RedisDbObject::new(
            object.clone(),
            owner.to_owned(),
            attributes.state.unwrap_or(State::PreActive),
            Some(tags.clone()),
            attributes.clone(),
        );
        let indexed_uid = IndexedValue::from(uid.as_bytes());
        for keyword in db_object.keywords() {
            self.findex.insert(keyword, [indexed_uid.clone()]).await?;
        }
        Ok((uid, db_object))
    }

    /// Update Findex index entries: insert new keywords, delete stale ones.
    async fn update_findex_keywords(
        &self,
        uid: &str,
        old_keywords: &HashSet<Keyword>,
        new_keywords: &HashSet<Keyword>,
    ) -> DbResult<()> {
        let indexed_uid = IndexedValue::from(uid.as_bytes());
        for keyword in new_keywords {
            self.findex
                .insert(keyword.clone(), [indexed_uid.clone()])
                .await?;
        }
        for keyword in old_keywords.difference(new_keywords) {
            self.findex
                .delete(keyword.clone(), [indexed_uid.clone()])
                .await?;
        }
        Ok(())
    }

    /// Delete all Findex index entries for the given object.
    async fn delete_findex_keywords(&self, uid: &str, keywords: &HashSet<Keyword>) -> DbResult<()> {
        let indexed_uid = IndexedValue::from(uid.as_bytes());
        for keyword in keywords {
            self.findex
                .delete(keyword.clone(), [indexed_uid.clone()])
                .await?;
        }
        Ok(())
    }

    async fn prepare_object_for_update(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        existing: Option<RedisDbObject>,
    ) -> DbResult<RedisDbObject> {
        let mut db_object = match existing {
            Some(obj) => obj,
            None => self
                .objects_db
                .object_get(uid)
                .await?
                .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?,
        };
        let old_keywords = db_object.keywords();
        db_object.object = object.clone();
        if tags.is_some() {
            db_object.tags = tags.cloned();
        }
        db_object.attributes = Some(attributes.clone());

        let new_keywords = db_object.keywords();
        self.update_findex_keywords(uid, &old_keywords, &new_keywords)
            .await?;
        Ok(db_object)
    }

    async fn prepare_object_for_state_update(
        &self,
        uid: &str,
        state: State,
        existing: Option<RedisDbObject>,
    ) -> DbResult<RedisDbObject> {
        let mut db_object = match existing {
            Some(obj) => obj,
            None => self
                .objects_db
                .object_get(uid)
                .await?
                .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?,
        };
        db_object.state = state;
        // The state is not indexed, so no Findex updates needed
        Ok(db_object)
    }

    // ── Ceremony helpers ────────────────────────────────────────────────────

    /// Derive an obfuscated Redis key name for a ceremony role using SHAKE-256.
    fn derive_ceremony_key_name(
        master_key: &Secret<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        role: &[u8],
    ) -> String {
        let mut hash = [0_u8; 8]; // 8 bytes → 16 hex chars
        kdf256!(&mut hash, &**master_key, b"ceremony_key_name", role);
        format!("c:{}", hex::encode(hash))
    }

    /// Derive an obfuscated Redis key name for a per-user ceremony record.
    fn derive_per_user_ceremony_key_name(&self, role: &str, user: &str) -> String {
        let mut hash = [0_u8; 8];
        let input = format!("{role}:{user}");
        kdf256!(&mut hash, &self.ceremony_derivation_key, input.as_bytes());
        format!("c:{}", hex::encode(hash))
    }

    /// Store a sealed ceremony record under the given Redis key.
    ///
    /// The record is a JSON object `{ "sealed": "<base64>", "revoked_at": null, "revoked_by": null }`.
    async fn store_ceremony_record(
        &self,
        redis_key: &str,
        sealed_record: &str,
    ) -> InterfaceResult<()> {
        let json = serde_json::json!({
            "sealed": sealed_record,
            "revoked_at": null,
            "revoked_by": null,
        });
        let value = serde_json::to_string(&json)
            .map_err(|e| InterfaceError::Default(format!("Failed to serialize ceremony: {e}")))?;
        redis::cmd("SET")
            .arg(redis_key)
            .arg(value)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to store ceremony: {e}")))?;
        Ok(())
    }

    /// Retrieve the sealed ceremony record from Redis, returning `None` if absent or revoked.
    async fn load_ceremony_record(&self, redis_key: &str) -> InterfaceResult<Option<String>> {
        let raw: Option<String> = redis::cmd("GET")
            .arg(redis_key)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to read ceremony: {e}")))?;
        match raw {
            None => Ok(None),
            Some(json_str) => {
                let v: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                    InterfaceError::Default(format!("Failed to parse ceremony record: {e}"))
                })?;
                // If revoked_at is set, treat as non-existent (revoked).
                if v.get("revoked_at").and_then(|v| v.as_str()).is_some() {
                    return Ok(None);
                }
                Ok(v.get("sealed").and_then(|s| s.as_str()).map(String::from))
            }
        }
    }

    /// Revoke the ceremony record at `redis_key` by setting `revoked_at` and `revoked_by`.
    async fn revoke_ceremony_record(
        &self,
        redis_key: &str,
        revoked_by: &str,
    ) -> InterfaceResult<()> {
        let raw: Option<String> = redis::cmd("GET")
            .arg(redis_key)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to read ceremony: {e}")))?;
        if let Some(json_str) = raw {
            let mut v: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                InterfaceError::Default(format!("Failed to parse ceremony record: {e}"))
            })?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "revoked_at".to_owned(),
                    serde_json::Value::String("revoked".to_owned()),
                );
                obj.insert(
                    "revoked_by".to_owned(),
                    serde_json::Value::String(revoked_by.to_owned()),
                );
            }
            let updated = serde_json::to_string(&v).map_err(|e| {
                InterfaceError::Default(format!("Failed to serialize ceremony record: {e}"))
            })?;
            redis::cmd("SET")
                .arg(redis_key)
                .arg(updated)
                .query_async::<()>(&mut self.mgr.clone())
                .await
                .map_err(|e| InterfaceError::Default(format!("Failed to update ceremony: {e}")))?;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl ObjectsStore for RedisWithFindex {
    /// Insert the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        owner: &UserId,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        let (uid, db_object) = self
            .prepare_object_for_create(uid, owner.as_str(), object, attributes, tags)
            .await?;

        // create the object
        self.objects_db.object_create(&uid, &db_object).await?;
        // New objects are always PreActive (live) — increment unconditionally.
        self.objects_db.adjust_live_count(1).await?;
        // New key objects are non-destroyed by definition — increment the key counter.
        if is_key_type(db_object.object_type) {
            self.objects_db.adjust_active_key_count(1).await?;
        }

        Ok(uid)
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        Ok(self.objects_db.object_get(uid).await.map(|o| {
            o.map(|o| {
                ObjectWithMetadata::new(
                    uid.to_owned(),
                    o.object,
                    o.owner,
                    o.state,
                    o.attributes.unwrap_or_default(),
                )
            })
        })?)
    }

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>> {
        Ok(self
            .objects_db
            .object_get(uid)
            .await?
            .map(|o| o.tags.unwrap_or_default())
            .unwrap_or_default())
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        let db_object = self
            .prepare_object_for_update(uid, object, attributes, tags, None)
            .await?;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        // Read the object once here so we can:
        //   1. Capture the old state for the counter delta.
        //   2. Pass it as `existing` to avoid a second object_get inside
        //      prepare_object_for_state_update.
        let existing = self.objects_db.object_get(uid).await?;
        let old_state = existing.as_ref().map(|o| o.state);

        let db_object = self
            .prepare_object_for_state_update(uid, state, existing)
            .await?;
        self.objects_db.object_upsert(uid, &db_object).await?;

        // Adjust counter only when the liveness crosses a boundary:
        //   live → destroyed  →  -1
        //   destroyed → live  →  +1
        //   no boundary cross →   0
        if let Some(old) = old_state {
            let delta = i64::from(is_live(state)) - i64::from(is_live(old));
            self.objects_db.adjust_live_count(delta).await?;
            // Mirror the same boundary check for the key counter.
            if is_key_type(db_object.object_type) {
                let key_delta = i64::from(!matches!(
                    state,
                    State::Destroyed | State::Destroyed_Compromised
                )) - i64::from(!matches!(
                    old,
                    State::Destroyed | State::Destroyed_Compromised
                ));
                self.objects_db.adjust_active_key_count(key_delta).await?;
            }
        }
        Ok(())
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        if let Some(db_object) = self.objects_db.object_get(uid).await? {
            self.delete_findex_keywords(uid, &db_object.keywords())
                .await?;
            self.objects_db.object_delete(uid).await?;
            // Only decrement for live objects — destroying an already-destroyed
            // object must not double-decrement the counter.
            if is_live(db_object.state) {
                self.objects_db.adjust_live_count(-1).await?;
            }
            // Decrement the key counter if this was a non-destroyed key object.
            if is_key_type(db_object.object_type) && is_live(db_object.state) {
                self.objects_db.adjust_active_key_count(-1).await?;
            }
        }
        Ok(())
    }

    async fn atomic(
        &self,
        user: &UserId,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        for attempt in 0..MAX_ATOMIC_CAS_ATTEMPTS {
            match self.try_atomic(user, operations).await? {
                AtomicAttempt::Committed(uids) => return Ok(uids),
                // Short growing pause so writers hammering one uid de-synchronise.
                AtomicAttempt::Retry => {
                    tokio::time::sleep(std::time::Duration::from_millis(u64::from(attempt.min(8))))
                        .await;
                }
            }
        }
        Err(db_error!(
            "atomic: exceeded {MAX_ATOMIC_CAS_ATTEMPTS} retries due to concurrent modifications"
        )
        .into())
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(&self, uid: &str, owner: &UserId) -> InterfaceResult<bool> {
        let object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?;
        Ok(object.owner == *owner)
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        let tag_keywords = tags
            .iter()
            .map(|tag| Keyword::from(tag.as_bytes()))
            .collect::<HashSet<Keyword>>();
        // find the indexed values that match at least one of the tags
        // TODO: upon release of `batch_findex`, use `batch_search` instead of `search`
        let mut uids_per_keyword = HashMap::with_capacity(tag_keywords.len());
        for keyword in tag_keywords {
            let search_result = self
                .findex
                .search(&keyword)
                .await
                .map_err(|e| db_error!(format!("Error while searching for tags: {e:?}")))?;
            uids_per_keyword.insert(keyword, search_result);
        }
        // convert to a vector of references to avoid cloning later on
        let indexed_values_set: Vec<HashSet<&IndexedValue>> = uids_per_keyword
            .values()
            .map(|set| set.iter().collect::<HashSet<_>>())
            .collect();
        // we want the intersection of all the results
        let uids = intersect_all_refs(&indexed_values_set)
            .into_iter()
            .collect::<HashSet<&IndexedValue>>();
        let uids = uids
            .into_iter()
            .map(|uid| {
                String::from_utf8(uid.to_vec())
                    .map_err(|e| db_error!(format!("Invalid uid. Error: {e:?}")))
            })
            .collect::<DbResult<HashSet<String>>>()?;
        // The index is updated after the object write, so a concurrent tag change
        // can leave a stale hit: keep only objects that really carry every tag.
        Ok(self
            .objects_db
            .objects_get(&uids)
            .await?
            .into_iter()
            .filter(|(_, object)| has_all_tags(object, tags))
            .map(|(uid, _)| uid)
            .collect())
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &UserId,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let searched_tags =
            researched_attributes.map_or_else(HashSet::new, |attrs| attrs.get_tags(vendor_id));
        let mut keywords = {
            researched_attributes.map_or_else(HashSet::new, |attributes| {
                let tags = attributes.get_tags(vendor_id);
                trace!("find: tags: {tags:?}");
                let mut keywords = tags
                    .iter()
                    .map(|tag| Keyword::from(tag.as_bytes()))
                    .collect::<HashSet<Keyword>>();
                // index some of the attributes
                keywords.extend(keywords_from_attributes(attributes));
                keywords
            })
        };
        if user_must_be_owner {
            trace!("find: user must be owner");
            keywords.insert(Keyword::from(user.as_bytes()));
        }
        // if there are now keywords, we return an empty list
        if keywords.is_empty() {
            return Ok(vec![]);
        }
        // search the keywords in the index
        let mut uids_per_keyword = HashMap::with_capacity(keywords.len());
        for keyword in keywords {
            let search_result = self
                .findex
                .search(&keyword)
                .await
                .map_err(|e| db_error!(format!("Error while searching for tags: {e:?}")))?;
            uids_per_keyword.insert(keyword, search_result);
        }

        let indexed_values_set: Vec<HashSet<&IndexedValue>> = uids_per_keyword
            .values()
            .map(|set| set.iter().collect::<HashSet<_>>())
            .collect();
        // we want the intersection of all the results
        let uids = intersect_all_refs(&indexed_values_set)
            .into_iter()
            .collect::<HashSet<&IndexedValue>>();

        let uids = uids
            .into_iter()
            .map(|uid| {
                String::from_utf8(uid.to_vec())
                    .map_err(|e| db_error!(format!("Invalid uid. Error: {e:?}")))
            })
            .collect::<DbResult<HashSet<String>>>()?;
        trace!("find: uids before permissions: {:?}", uids);
        // if the user is not the owner, we need to check the permissions
        let permissions = if user_must_be_owner {
            HashMap::new()
        } else {
            self.permission_db
                .list_user_permissions(&FindexUserId(user.as_str().to_owned()))
                .await?
                .into_iter()
                .map(|(k, v)| (k.0, v))
                .collect()
        };

        // fetch the corresponding objects
        let redis_db_objects = self.objects_db.objects_get(&uids).await?;
        Ok(redis_db_objects
            .into_iter()
            .filter(|(uid, redis_db_object)| {
                has_all_tags(redis_db_object, &searched_tags)
                    && state.is_none_or(|state| redis_db_object.state == state)
                    && (if redis_db_object.owner == *user {
                        true
                    } else {
                        permissions.contains_key(uid)
                    })
            })
            .map(|(uid, redis_db_object)| {
                (
                    uid,
                    redis_db_object.state,
                    redis_db_object
                        .object
                        .attributes()
                        .cloned()
                        .unwrap_or_else(|_| Attributes {
                            object_type: Some(redis_db_object.object.object_type()),
                            ..Default::default()
                        }),
                )
            })
            .collect())
    }

    async fn find_all(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        // Redis does not support a bypass-all-user-filtering scan via Findex.
        // Fall back to a full SCAN of the object store and filter by attributes/state.
        let all_objects = self.objects_db.scan_all_objects().await?;
        let results = all_objects
            .into_iter()
            .filter(|(_uid, obj)| {
                if state.is_some_and(|s| obj.state != s) {
                    return false;
                }
                if let Some(attrs) = researched_attributes {
                    // Filter by object_type if specified.
                    if let Some(required_type) = attrs.object_type {
                        if obj.object_type != required_type {
                            return false;
                        }
                    }

                    // Filter by tags if specified.
                    let tags = attrs.get_tags(vendor_id);
                    if !tags.is_empty() {
                        let obj_tags = obj
                            .object
                            .attributes()
                            .map(|a| a.get_tags(vendor_id))
                            .unwrap_or_default();
                        if !tags.iter().all(|t| obj_tags.contains(t)) {
                            return false;
                        }
                    }

                    // Filter by link attributes if specified — each required link must
                    // appear in the object's own link list (matched by type and identifier).
                    // Use the dedicated `attributes` field (covers Certificate objects
                    // which have no key block and would return an error from
                    // `obj.object.attributes()`).
                    if let Some(required_links) = &attrs.link {
                        if !required_links.is_empty() {
                            let obj_links = obj
                                .attributes
                                .as_ref()
                                .and_then(|a| a.link.as_deref())
                                .unwrap_or(&[]);
                            for req in required_links {
                                let found = obj_links.iter().any(|l| {
                                    l.link_type == req.link_type
                                        && l.linked_object_identifier
                                            == req.linked_object_identifier
                                });
                                if !found {
                                    return false;
                                }
                            }
                        }
                    }
                }
                true
            })
            .map(|(uid, obj)| {
                let attrs = obj
                    .object
                    .attributes()
                    .cloned()
                    .unwrap_or_else(|_| Attributes {
                        object_type: Some(obj.object.object_type()),
                        ..Default::default()
                    });
                (uid, obj.state, attrs)
            })
            .collect();
        Ok(results)
    }

    async fn find_by_rotate_name(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &UserId,
    ) -> InterfaceResult<Vec<(String, Attributes)>> {
        // Search Findex for objects indexed under this rotate_name keyword
        let keyword = Keyword::from(format!("rotate_name::{name}").as_bytes());
        let indexed_uids = self
            .findex
            .search(&keyword)
            .await
            .map_err(|e| db_error!(format!("Error searching rotate_name keyword: {e:?}")))?;
        if indexed_uids.is_empty() {
            return Ok(vec![]);
        }

        let candidate_uids: HashSet<String> = indexed_uids
            .iter()
            .filter_map(|v| String::from_utf8(v.to_vec()).ok())
            .collect();

        // Fetch the candidate objects
        let redis_db_objects = self.objects_db.objects_get(&candidate_uids).await?;

        // Filter by owner, generation, and latest flag
        let mut results = Vec::new();
        for (uid, dbo) in redis_db_objects {
            if dbo.owner != *owner {
                continue;
            }
            let attrs = dbo.attributes.unwrap_or_default();
            // Filter by generation if requested
            if let Some(expected_gen) = generation {
                if attrs.rotate_generation != Some(expected_gen) {
                    continue;
                }
            }
            results.push((uid, attrs));
        }
        Ok(results)
    }

    async fn find_wrapped_by(
        &self,
        wrapping_key_uid: &str,
        user: &UserId,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        // Search Findex for objects indexed under this wrapping key
        let keyword = Keyword::from(format!("wrapped_by::{wrapping_key_uid}").as_bytes());
        let indexed_uids = self
            .findex
            .search(&keyword)
            .await
            .map_err(|e| db_error!(format!("Error searching wrapped_by keyword: {e:?}")))?;
        if indexed_uids.is_empty() {
            return Ok(vec![]);
        }

        let candidate_uids: HashSet<String> = indexed_uids
            .iter()
            .filter_map(|v| String::from_utf8(v.to_vec()).ok())
            .collect();

        // Fetch only the candidate objects
        let redis_db_objects = self.objects_db.objects_get(&candidate_uids).await?;

        // Filter by access: user must own the object or have permissions on it
        let permissions = self
            .permission_db
            .list_user_permissions(&FindexUserId(user.as_str().to_owned()))
            .await?;

        let mut out = Vec::new();
        for (uid, dbo) in redis_db_objects {
            let has_access =
                dbo.owner == *user || permissions.contains_key(&ObjectUid(uid.clone()));
            if !has_access {
                continue;
            }
            let attrs = dbo
                .object
                .attributes()
                .cloned()
                .unwrap_or_else(|_| Attributes {
                    object_type: Some(dbo.object.object_type()),
                    ..Default::default()
                });
            out.push((uid, dbo.state, attrs));
        }
        Ok(out)
    }

    /// Scan all objects and return `(uid, owner)` pairs for `Active` objects
    /// with `rotate_automatic = true` whose next rotation instant is ≤ `now`.
    ///
    /// Implemented as an O(N) Redis SCAN.  Acceptable cost because this method
    /// is only called by the low-frequency auto-rotation cron scheduler.
    async fn find_due_for_rotation(
        &self,
        now: time::OffsetDateTime,
    ) -> InterfaceResult<Vec<(String, String)>> {
        self.objects_db
            .scan_due_for_rotation(now)
            .await
            .map_err(InterfaceError::from)
    }

    /// Return the count of live (non-destroyed) objects.
    ///
    /// # Fast path (steady state)
    ///
    /// Reads a single counter key `kms::metrics::live_object_count` that is
    /// incremented/decremented in sync with every mutating operation in this
    /// backend.  Cost: one O(1) `GET`, no decryption.
    ///
    /// # Bootstrap (first boot or after `FLUSHDB`)
    ///
    /// When the counter key is absent (counter has never been initialised or
    /// was manually deleted), a one-time SCAN of all `do::*` keys is performed,
    /// each blob is decrypted, and the result is written to the counter key.
    /// Subsequent calls return the fast path immediately.
    async fn count_all_non_destroyed(&self) -> InterfaceResult<u64> {
        // Fast path: counter key already exists.
        if let Some(count) = self.objects_db.get_live_count().await? {
            return Ok(count);
        }
        // Bootstrap: scan + decrypt once to establish the baseline.
        let count = self.objects_db.scan_count_non_destroyed().await?;
        self.objects_db.set_live_count(count).await?;
        debug!(
            "[redis-metrics] bootstrapped {} live object(s) into `{}`",
            count, LIVE_COUNT_KEY
        );
        Ok(count)
    }

    /// Count non-destroyed key objects (`SymmetricKey`, `PrivateKey`, `PublicKey`, `SplitKey`).
    ///
    /// # Fast path
    /// When `ACTIVE_KEY_COUNT_KEY` exists: one O(1) `GET`, no decryption.
    ///
    /// # Bootstrap
    /// When the key is absent (first boot or after `FLUSHDB`): scans all `do::*`
    /// keys, decrypts each, filters by key type and non-destroyed state, writes
    /// the result to `ACTIVE_KEY_COUNT_KEY`, and returns the count.
    async fn count_non_destroyed_keys(&self) -> InterfaceResult<u64> {
        if let Some(count) = self.objects_db.get_active_key_count().await? {
            return Ok(count);
        }
        let count = self.objects_db.scan_count_non_destroyed_keys().await?;
        self.objects_db.set_active_key_count(count).await?;
        debug!(
            "[redis-metrics] bootstrapped {} non-destroyed key(s) into `{}`",
            count, ACTIVE_KEY_COUNT_KEY
        );
        Ok(count)
    }

    /// Authoritative reconcile: recompute both Redis counter keys from a full
    /// SCAN and overwrite the cached values.
    ///
    /// Called by the slow-path cron loop (every 5 minutes) to prevent counter
    /// drift from accumulating due to partial failures.  The O(N) scan cost is
    /// acceptable at that frequency.
    async fn reconcile_counts(&self) -> InterfaceResult<()> {
        let live_count = self.objects_db.scan_count_non_destroyed().await?;
        self.objects_db.set_live_count(live_count).await?;
        let key_count = self.objects_db.scan_count_non_destroyed_keys().await?;
        self.objects_db.set_active_key_count(key_count).await?;
        debug!(
            "[redis-metrics] reconcile: live_objects={live_count}, non_destroyed_keys={key_count}"
        );
        Ok(())
    }
}

#[async_trait(?Send)]
impl PermissionsStore for RedisWithFindex {
    async fn list_user_operations_granted(
        &self,
        user: &UserId,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        let permissions = self
            .permission_db
            .list_user_permissions(&FindexUserId(user.as_str().to_owned()))
            .await?;
        let mut redis_db_objects = self
            .objects_db
            .objects_get(
                &permissions
                    .keys()
                    .map(|k| (*k).clone().into())
                    .collect::<HashSet<String>>(),
            )
            .await?;
        // Join by uid rather than zipping the two maps by iteration order:
        // `permissions` and `redis_db_objects` are independent `HashMap`s whose
        // iteration orders are not guaranteed to correspond, and `objects_get`
        // may legitimately return fewer entries (e.g. a stale permission for an
        // object that no longer exists). Missing objects are skipped.
        Ok(permissions
            .into_iter()
            .filter_map(|(uid, permissions)| {
                let uid_string: String = uid.into();
                let redis_db_object = redis_db_objects.remove(&uid_string)?;
                Some((
                    uid_string,
                    (
                        redis_db_object.owner,
                        redis_db_object.state,
                        permissions.into_iter().collect::<HashSet<KmipOperation>>(),
                    ),
                ))
            })
            .collect())
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(self
            .permission_db
            .list_object_permissions(&ObjectUid(uid.to_owned()))
            .await?
            .into_iter()
            .map(|(k, v)| (k.0, v.into_iter().collect()))
            .collect::<HashMap<_, _>>())
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        for operation in &operations {
            self.permission_db
                .add(
                    &ObjectUid(uid.to_owned()),
                    &FindexUserId(user.as_str().to_owned()),
                    *operation,
                )
                .await?;
        }
        Ok(())
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        for operation in &operations {
            self.permission_db
                .remove(
                    &ObjectUid(uid.to_owned()),
                    &FindexUserId(user.as_str().to_owned()),
                    *operation,
                )
                .await?;
        }
        Ok(())
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &UserId,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        Ok(self
            .permission_db
            .get(
                &ObjectUid(uid.to_owned()),
                &FindexUserId(user.as_str().to_owned()),
                no_inherited_access,
            )
            .await
            .unwrap_or_default()
            .into_iter()
            .collect())
    }

    async fn upsert_crl(
        &self,
        issuer_id: &str,
        crl_der: &[u8],
        crl_number: u64,
        generated_at: &str,
        next_update: &str,
    ) -> InterfaceResult<()> {
        // Store as a JSON blob keyed by "crl:<issuer_id>".
        let key = format!("crl:{issuer_id}");
        let json = serde_json::json!({
            "crl_der": crl_der,
            "crl_number": crl_number,
            "generated_at": generated_at,
            "next_update": next_update,
        });
        let value = serde_json::to_string(&json).map_err(|e| {
            InterfaceError::Default(format!("Failed to serialize CRL for Redis: {e}"))
        })?;
        redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to store CRL in Redis: {e}")))?;
        Ok(())
    }

    async fn get_crl(&self, issuer_id: &str) -> InterfaceResult<Option<(Vec<u8>, String)>> {
        let key = format!("crl:{issuer_id}");
        let raw: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to read CRL from Redis: {e}")))?;
        let Some(json_str) = raw else {
            return Ok(None);
        };
        let v: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| InterfaceError::Default(format!("Failed to parse CRL from Redis: {e}")))?;
        let der = v
            .get("crl_der")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());
        let generated_at = v
            .get("generated_at")
            .and_then(|s| s.as_str())
            .map(String::from);
        match (der, generated_at) {
            (Some(der), Some(generated_at)) => Ok(Some((der, generated_at))),
            _ => Ok(None),
        }
    }

    async fn list_crl_issuers(&self) -> InterfaceResult<Vec<(String, String)>> {
        // Scan for all keys matching the `crl:*` pattern.
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("crl:*")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                InterfaceError::Default(format!("Failed to list CRL keys from Redis: {e}"))
            })?;

        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            let raw: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut self.mgr.clone())
                .await
                .map_err(|e| {
                    InterfaceError::Default(format!("Failed to read CRL key '{key}': {e}"))
                })?;
            let Some(json_str) = raw else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json_str) else {
                continue;
            };
            let Some(next_update) = v
                .get("next_update")
                .and_then(|s| s.as_str())
                .map(String::from)
            else {
                continue;
            };
            // Strip the "crl:" prefix to get the issuer_id.
            let issuer_id = key.strip_prefix("crl:").unwrap_or(&key).to_owned();
            result.push((issuer_id, next_update));
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }

    async fn get_max_crl_number(&self) -> InterfaceResult<Option<u64>> {
        // Scan all CRL keys and return the maximum stored crl_number.
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("crl:*")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                InterfaceError::Default(format!(
                    "Failed to list CRL keys from Redis for max_crl_number: {e}"
                ))
            })?;

        let mut max_number: Option<u64> = None;
        for key in keys {
            let raw: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut self.mgr.clone())
                .await
                .map_err(|e| {
                    InterfaceError::Default(format!("Failed to read CRL key '{key}': {e}"))
                })?;
            let Some(json_str) = raw else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json_str) else {
                continue;
            };
            let Some(n) = v.get("crl_number").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            max_number = Some(max_number.map_or(n, |prev| prev.max(n)));
        }
        Ok(max_number)
    }

    async fn activate_crypto_officer_ceremony(
        &self,
        sealed_record: &str,
        activated_by: &str,
        revoked_by: &str,
    ) -> InterfaceResult<()> {
        // For Redis, per-user ceremony records use a per-user obfuscated key.
        // `SET` is atomic — it replaces any prior record for this user, so the
        // revoke of the same user's prior record and the new insert are one operation.
        let user_key = self.derive_per_user_ceremony_key_name("crypto_officer", activated_by);
        // Revoke any prior record for this user.
        self.revoke_ceremony_record(&user_key, revoked_by).await?;
        // Store the new sealed record.
        self.store_ceremony_record(&user_key, sealed_record).await?;
        // Add to the active-COs set.
        redis::cmd("SADD")
            .arg(&self.ceremony_active_cos_key)
            .arg(activated_by)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                InterfaceError::Default(format!("Failed to add to active COs set: {e}"))
            })?;
        Ok(())
    }

    async fn get_crypto_officer_activation_by(
        &self,
        user: &str,
    ) -> InterfaceResult<Option<String>> {
        let user_key = self.derive_per_user_ceremony_key_name("crypto_officer", user);
        self.load_ceremony_record(&user_key).await
    }

    async fn is_any_crypto_officer_activated(&self) -> InterfaceResult<bool> {
        let count: i64 = redis::cmd("SCARD")
            .arg(&self.ceremony_active_cos_key)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| InterfaceError::Default(format!("Failed to read active COs set: {e}")))?;
        Ok(count > 0)
    }

    async fn revoke_crypto_officer_activation(
        &self,
        revoked_by: &str,
        activated_by: &str,
    ) -> InterfaceResult<()> {
        let user_key = self.derive_per_user_ceremony_key_name("crypto_officer", activated_by);
        self.revoke_ceremony_record(&user_key, revoked_by).await?;
        // Remove from the active-COs set.
        redis::cmd("SREM")
            .arg(&self.ceremony_active_cos_key)
            .arg(activated_by)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                InterfaceError::Default(format!("Failed to remove from active COs set: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmian_findex::IndexADT as _;
    use cosmian_kmip::kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
        kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
    };
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng, Secret, reexport::rand_core::SeedableRng,
    };
    use cosmian_kms_interfaces::{ObjectsStore as _, UserId};
    use uuid::Uuid;

    use crate::{
        stores::{
            REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
            redis::{
                RedisWithFindex,
                findex::{IndexedValue, Keyword},
            },
        },
        tests::get_redis_url,
    };

    /// A Findex hit whose tag the stored object does not carry (stale index entry,
    /// e.g. from out-of-order post-commit index updates) must not be returned.
    #[allow(clippy::panic_in_result_fn)] // test assertions must panic; `?` keeps setup errors readable
    #[ignore = "Requires a running Redis instance"]
    #[tokio::test]
    async fn stale_findex_hit_is_filtered_out() -> crate::error::DbResult<()> {
        let mut rng = CsRng::from_entropy();
        let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
        let store = RedisWithFindex::instantiate(&get_redis_url(), master_key, false).await?;
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let real_tag = format!("real-{uid}");
        let stale_tag = format!("stale-{uid}");
        let object = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[7_u8; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?;
        store
            .create(
                Some(uid.clone()),
                &owner,
                &object,
                object.attributes()?,
                &HashSet::from([real_tag.clone()]),
            )
            .await?;
        store
            .findex
            .insert(
                Keyword::from(stale_tag.as_bytes()),
                [IndexedValue::from(uid.as_bytes())],
            )
            .await?;

        let real = store
            .list_uids_for_tags(&HashSet::from([real_tag.clone()]))
            .await?;
        let stale = store
            .list_uids_for_tags(&HashSet::from([stale_tag.clone()]))
            .await?;
        assert!(real.contains(&uid), "real tag must select the object");
        assert!(stale.is_empty(), "stale hit returned: {stale:?}");

        let mut attributes = Attributes::default();
        attributes.set_tags(VENDOR_ID_COSMIAN, HashSet::from([stale_tag]))?;
        let found = store
            .find(Some(&attributes), None, &owner, true, VENDOR_ID_COSMIAN)
            .await?;
        assert!(found.is_empty(), "find returned stale hit: {found:?}");
        Ok(())
    }

    #[test]
    fn test_intersect() {
        let set1: HashSet<_> = vec![
            IndexedValue::from(b"1".as_slice()),
            IndexedValue::from(b"2".as_slice()),
            IndexedValue::from(b"3".as_slice()),
            IndexedValue::from(b"4".as_slice()),
        ]
        .into_iter()
        .collect();
        let set2: HashSet<_> = vec![
            IndexedValue::from(b"2".as_slice()),
            IndexedValue::from(b"3".as_slice()),
            IndexedValue::from(b"4".as_slice()),
            IndexedValue::from(b"5".as_slice()),
        ]
        .into_iter()
        .collect();
        let set3: HashSet<_> = vec![
            IndexedValue::from(b"3".as_slice()),
            IndexedValue::from(b"4".as_slice()),
            IndexedValue::from(b"5".as_slice()),
            IndexedValue::from(b"6".as_slice()),
        ]
        .into_iter()
        .collect();

        // Create references to the IndexedValues
        let ref_set1: HashSet<&IndexedValue> = set1.iter().collect();
        let ref_set2: HashSet<&IndexedValue> = set2.iter().collect();
        let ref_set3: HashSet<&IndexedValue> = set3.iter().collect();

        // Create a Vec of HashSets with references
        let sets = vec![ref_set1, ref_set2, ref_set3];

        let res = super::intersect_all_refs(&sets);
        assert_eq!(res.len(), 2);
        assert!(res.contains(&IndexedValue::from(b"3".as_slice())));
        assert!(res.contains(&IndexedValue::from(b"4".as_slice())));
    }
}

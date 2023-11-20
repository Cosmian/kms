use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{RandomFixedSizeCBytes, SymmetricKey};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Sqlite,
};
use tracing::trace;

use super::{
    cached_sqlite_struct::KMSSqliteCache,
    object_with_metadata::ObjectWithMetadata,
    sqlite::{
        create_, delete_, find_, insert_access_, is_object_owned_by_, list_accesses_,
        list_user_granted_access_rights_, remove_access_, retrieve_, update_object_, update_state_,
        upsert_,
    },
};
use crate::{
    database::{
        database_trait::AtomicOperation,
        sqlite::{atomic_, retrieve_tags_},
        Database, SQLITE_QUERIES,
    },
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

pub struct CachedSqlCipher {
    path: PathBuf,
    cache: KMSSqliteCache,
}

// We allow 100 opened connection
const KMS_SQLITE_CACHE_SIZE: usize = 100;

impl CachedSqlCipher {
    /// Instantiate a new `CachedSqlCipher`
    /// and create the appropriate table(s) if need be
    pub async fn instantiate(path: &Path, clear_database: bool) -> KResult<Self> {
        if clear_database && path.exists() && path.is_dir() {
            remove_dir_content(path)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            cache: KMSSqliteCache::new(KMS_SQLITE_CACHE_SIZE),
        })
    }

    async fn instantiate_group_database(
        &self,
        group_id: u128,
        key: &SymmetricKey<32>,
    ) -> KResult<Pool<Sqlite>> {
        let path = self
            .filename(group_id)
            .ok_or_else(|| kms_error!("Path for group database does not exist"))?;
        let options = SqliteConnectOptions::new()
            // create the database file if it doesn't exist
            .create_if_missing(true)
            .pragma("key", format!("\"x'{}'\"", hex::encode(key.as_bytes())))
            .pragma("journal_mode", "OFF")
            .filename(path)
            // Sets a timeout value to wait when the database is locked, before returning a busy timeout error.
            .busy_timeout(Duration::from_secs(120))
            // disable logging of each query
            .disable_statement_logging();

        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .context("Failed to connect to SQCipher database")
    }

    async fn create_tables(pool: &Pool<Sqlite>) -> KResult<()> {
        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-tags")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    fn post_query(&self, group_id: u128) -> KResult<()> {
        self.cache.release(group_id)
    }

    async fn pre_query(
        &self,
        group_id: u128,
        key: &SymmetricKey<32>,
    ) -> KResult<Arc<Pool<Sqlite>>> {
        if !self.cache.exists(group_id) {
            let pool = self.instantiate_group_database(group_id, key).await?;
            Self::create_tables(&pool).await?;
            self.cache.save(group_id, key, pool).await?;
        } else if !self.cache.opened(group_id) {
            let pool = self.instantiate_group_database(group_id, key).await?;
            self.cache.save(group_id, key, pool).await?;
        }

        self.cache.get(group_id, key)
    }
}

#[async_trait(?Send)]
impl Database for CachedSqlCipher {
    fn filename(&self, group_id: u128) -> Option<PathBuf> {
        Some(self.path.join(format!("{group_id}.sqlite")))
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            match create_(uid, owner, object, tags, &mut tx).await {
                Ok(uid) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(uid)
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    kms_bail!("creation of object failed: {}", e)
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn create_objects(
        &self,
        owner: &str,
        objects: Vec<(Option<String>, Object, &HashSet<String>)>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut res = vec![];
            let mut tx = pool.begin().await?;
            for (uid, object, tags) in objects {
                match create_(uid.clone(), owner, &object, tags, &mut tx).await {
                    Ok(uid) => res.push(uid),
                    Err(e) => {
                        tx.rollback().await.context("transaction failed")?;
                        self.post_query(params.group_id)?;
                        kms_bail!("creation of objects failed: {}", e);
                    }
                };
            }
            tx.commit().await?;
            self.post_query(params.group_id)?;

            return Ok(res)
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn retrieve(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_(uid, user, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn retrieve_tags(
        &self,
        uid: &UniqueIdentifier,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_tags_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_object(
        &self,
        uid: &UniqueIdentifier,
        object: &Object,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            match update_object_(uid, object, tags, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    kms_bail!("creation of object failed: {}", e)
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_state(
        &self,
        uid: &UniqueIdentifier,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            match update_state_(uid, state, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    kms_bail!("update of state of object {uid} failed: {e}")
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn upsert(
        &self,
        uid: &UniqueIdentifier,
        user: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            match upsert_(uid, user, object, tags, state, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    kms_bail!("upsert of object failed: {}", e)
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn delete(
        &self,
        uid: &UniqueIdentifier,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            match delete_(uid, owner, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    kms_bail!("deletion of object failed: {}", e)
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_user_granted_access_rights(
        &self,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<UniqueIdentifier, (String, StateEnumeration, HashSet<ObjectOperationType>)>>
    {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_user_granted_access_rights_(owner, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_object_accesses_granted(
        &self,
        uid: &UniqueIdentifier,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_accesses_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn grant_access(
        &self,
        uid: &UniqueIdentifier,
        userid: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = insert_access_(uid, userid, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn remove_access(
        &self,
        uid: &UniqueIdentifier,
        userid: &str,
        operation_type: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = remove_access_(uid, userid, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn is_object_owned_by(
        &self,
        uid: &UniqueIdentifier,
        userid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = is_object_owned_by_(uid, userid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        trace!("cached sqlcipher: find: {:?}", researched_attributes);
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = find_(
                researched_attributes,
                state,
                user,
                user_must_be_owner,
                &*pool,
            )
            .await;
            trace!("cached sqlcipher: before post_query: {:?}", ret);
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_user_access_rights_on_object(
        &self,
        uid: &UniqueIdentifier,
        userid: &str,
        no_inherited_access: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        use super::sqlite::list_user_access_rights_on_object_;

        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret =
                list_user_access_rights_on_object_(uid, userid, no_inherited_access, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn atomic(
        &self,
        owner: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let mut tx = pool.begin().await?;
            return match atomic_(owner, operations, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    Err(e)
                }
            }
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }
}

fn remove_dir_content(path: &Path) -> Result<(), std::io::Error> {
    let dir = std::fs::read_dir(path)?;
    for entry in dir {
        let path = entry?.path();
        if path.is_dir() {
            remove_dir_content(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

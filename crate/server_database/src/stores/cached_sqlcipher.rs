use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use clap::crate_version;
use cosmian_kmip::{
    crypto::{secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH},
    kmip::{
        kmip_objects::Object,
        kmip_types::{Attributes, StateEnumeration},
        KmipOperation,
    },
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Row, Sqlite,
};
use tracing::{debug, trace};

use super::{
    cached_sqlite_struct::KMSSqliteCache,
    sqlite::{
        create_, delete_, find_, insert_access_, is_object_owned_by_, list_accesses_,
        list_user_granted_access_rights_, remove_access_, retrieve_, update_object_, update_state_,
    },
    ExtraStoreParams,
};
use crate::{
    db_bail, db_error,
    error::DbResultHelper,
    get_sqlite_query,
    migrate::do_migration,
    stores::{
        sqlite::{
            atomic_, is_migration_in_progress_, list_uids_for_tags_, migrate_, retrieve_tags_,
        },
        store_traits::{AtomicOperation, ObjectsStore, PermissionsStore},
        SQLITE_QUERIES,
    },
    DbResult, ObjectWithMetadata, KMS_VERSION_BEFORE_MIGRATION_SUPPORT,
};

#[derive(Clone)]
pub struct CachedSqlCipher {
    path: PathBuf,
    cache: Arc<KMSSqliteCache>,
}

// We allow 100 opened connection
const KMS_SQLITE_CACHE_SIZE: usize = 100;

impl CachedSqlCipher {
    /// Instantiate a new `CachedSqlCipher`
    /// and create the appropriate table(s) if need be
    pub(crate) fn instantiate(path: &Path, clear_database: bool) -> DbResult<Self> {
        if clear_database && path.exists() && path.is_dir() {
            remove_dir_content(path)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            cache: Arc::new(KMSSqliteCache::new(KMS_SQLITE_CACHE_SIZE)),
        })
    }

    async fn instantiate_group_database(
        &self,
        group_id: u128,
        key: &Secret<AES_256_GCM_KEY_LENGTH>,
    ) -> DbResult<Pool<Sqlite>> {
        let path = self
            .filename(group_id)
            .ok_or_else(|| db_error!("Path for group database does not exist"))?;
        let options = SqliteConnectOptions::new()
            // create the database file if it doesn't exist
            .create_if_missing(true)
            .pragma("key", format!("\"x'{}'\"", hex::encode(&**key)))
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

    async fn create_tables(pool: &Pool<Sqlite>) -> DbResult<()> {
        sqlx::query(get_sqlite_query!("create-table-context"))
            .execute(pool)
            .await?;

        sqlx::query(get_sqlite_query!("create-table-objects"))
            .execute(pool)
            .await?;

        sqlx::query(get_sqlite_query!("create-table-read_access"))
            .execute(pool)
            .await?;

        sqlx::query(get_sqlite_query!("create-table-tags"))
            .execute(pool)
            .await?;

        Ok(())
    }

    fn post_query(&self, group_id: u128) -> DbResult<()> {
        self.cache.release(group_id)
    }

    async fn pre_query(
        &self,
        group_id: u128,
        key: &Secret<AES_256_GCM_KEY_LENGTH>,
    ) -> DbResult<Arc<Pool<Sqlite>>> {
        if !self.cache.exists(group_id)? {
            let pool = self.instantiate_group_database(group_id, key).await?;
            Self::create_tables(&pool).await?;
            self.cache.save(group_id, key, pool).await?;
        } else if !self.cache.opened(group_id)? {
            let pool = self.instantiate_group_database(group_id, key).await?;
            self.cache.save(group_id, key, pool).await?;
        }

        self.cache.get(group_id, key)
    }
}

#[async_trait(?Send)]
impl ObjectsStore for CachedSqlCipher {
    fn filename(&self, group_id: u128) -> Option<PathBuf> {
        Some(self.path.join(format!("{group_id}.sqlite")))
    }

    async fn migrate(&self, params: Option<&ExtraStoreParams>) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;

            trace!("Migrate database");
            // Get the context rows
            match sqlx::query(get_sqlite_query!("select-context"))
                .fetch_optional(&*pool)
                .await?
            {
                None => {
                    trace!("No context row found, migrating from scratch");
                    return migrate_(
                        &pool,
                        KMS_VERSION_BEFORE_MIGRATION_SUPPORT,
                        "insert-context",
                    )
                    .await;
                }
                Some(context_row) => {
                    let last_kms_version_run = context_row.get::<String, _>(0);
                    let state = context_row.get::<String, _>(1);
                    trace!(
                        "Context row found, migrating from version {last_kms_version_run} (state: \
                         {state})"
                    );
                    let current_kms_version = crate_version!();
                    debug!(
                        "[state={state}] Last KMS version run: {last_kms_version_run}, Current \
                         KMS version: {current_kms_version}"
                    );

                    if do_migration(&last_kms_version_run, current_kms_version, &state)? {
                        return migrate_(&pool, current_kms_version, "update-context").await;
                    }
                }
            }

            return Ok(());
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<String> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }

            let mut tx = pool.begin().await?;
            match create_(uid, owner, object, attributes, tags, &mut tx).await {
                Ok(uid) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(uid)
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    db_bail!("creation of object failed: {}", e)
                }
            }
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn retrieve(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_tags_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }

            let mut tx = pool.begin().await?;
            match update_object_(uid, object, attributes, tags, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    db_bail!("creation of object failed: {}", e)
                }
            }
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }
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
                    db_bail!("update of state of object {uid} failed: {e}")
                }
            }
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn delete(&self, uid: &str, params: Option<&ExtraStoreParams>) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }
            let mut tx = pool.begin().await?;
            match delete_(uid, &mut tx).await {
                Ok(()) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    db_bail!("deletion of object failed: {}", e)
                }
            }
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<String>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }
            let mut tx = pool.begin().await?;
            return match atomic_(user, operations, &mut tx).await {
                Ok(v) => {
                    tx.commit().await?;
                    self.post_query(params.group_id)?;
                    Ok(v)
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    Err(e)
                }
            }
        }
        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<bool> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = is_object_owned_by_(uid, owner, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_uids_for_tags_(tags, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<(String, StateEnumeration, Attributes)>> {
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

        db_bail!("Missing group_id/key for opening SQLCipher")
    }
}
#[async_trait(?Send)]
impl PermissionsStore for CachedSqlCipher {
    async fn list_user_operations_granted(
        &self,
        user: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_user_granted_access_rights_(user, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_accesses_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }
            let ret = insert_access_(uid, user, operation_types, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            if is_migration_in_progress_(&*pool).await? {
                db_bail!("Migration in progress. Please retry later");
            }
            let ret = remove_access_(uid, user, operation_types, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<KmipOperation>> {
        use super::sqlite::list_user_access_rights_on_object_;

        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret =
                list_user_access_rights_on_object_(uid, user, no_inherited_access, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        db_bail!("Missing group_id/key for opening SQLCipher")
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

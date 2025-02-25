use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
    KmipOperation,
};
use cosmian_kms_crypto::crypto::{
    secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH,
};
use cosmian_kms_interfaces::{
    AtomicOperation, DbState, InterfaceError, InterfaceResult, Migrate, ObjectWithMetadata,
    ObjectsStore, PermissionsStore, SessionParams,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Sqlite,
};
use tracing::trace;

use super::{
    cached_sqlite_struct::KMSSqliteCache,
    sqlite::{
        create_, delete_, find_, insert_access_, is_object_owned_by_, list_accesses_,
        list_user_granted_access_rights_, remove_access_, retrieve_, update_object_, update_state_,
    },
    SqlCipherSessionParams,
};
use crate::{
    db_error,
    error::{DbResult, DbResultHelper},
    get_sqlite_query,
    stores::{
        sqlite::{atomic_, list_uids_for_tags_, retrieve_tags_},
        SQLITE_QUERIES,
    },
};

#[derive(Clone)]
pub(crate) struct CachedSqlCipher {
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
        sqlx::query(get_sqlite_query!("create-table-parameters"))
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

        // Old table context used between version 4.13.0 and 4.22.1
        let _ = sqlx::query("DROP TABLE context").execute(pool).await;

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

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| InterfaceError::Db(format!("Failed to start transaction: {e}")))?;
            match create_(uid, owner, object, attributes, tags, &mut tx).await {
                Ok(uid) => {
                    tx.commit().await.map_err(|e| {
                        InterfaceError::Db(format!("Failed to commit transaction: {e}"))
                    })?;
                    self.post_query(params.group_id)?;
                    return Ok(uid)
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    return Err(InterfaceError::Db(format!(
                        "creation of object failed: {e}"
                    )));
                }
            }
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn retrieve(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_tags_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| InterfaceError::Db(format!("Failed to start transaction: {e}")))?;
            match update_object_(uid, object, attributes, tags, &mut tx).await {
                Ok(()) => {
                    tx.commit().await.map_err(|e| {
                        InterfaceError::Db(format!("Failed to commit transaction: {e}"))
                    })?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    return Err(InterfaceError::Db(format!(
                        "creation of object failed: {e}"
                    )));
                }
            }
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| InterfaceError::Db(format!("Failed to start transaction: {e}")))?;
            match update_state_(uid, state, &mut tx).await {
                Ok(()) => {
                    tx.commit().await.map_err(|e| {
                        InterfaceError::Db(format!("Failed to commit transaction: {e}"))
                    })?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    return Err(InterfaceError::Db(format!(
                        "update of state of object {uid} failed: {e}"
                    )));
                }
            }
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn delete(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| InterfaceError::Db(format!("Failed to start transaction: {e}")))?;
            match delete_(uid, &mut tx).await {
                Ok(()) => {
                    tx.commit().await.map_err(|e| {
                        InterfaceError::Db(format!("Failed to commit transaction: {e}"))
                    })?;
                    self.post_query(params.group_id)?;
                    return Ok(())
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    return Err(InterfaceError::Db(format!(
                        "deletion of object failed: {e}"
                    )));
                }
            }
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| InterfaceError::Db(format!("Failed to start transaction: {e}")))?;
            return match atomic_(user, operations, &mut tx).await {
                Ok(v) => {
                    tx.commit().await.map_err(|e| {
                        InterfaceError::Db(format!("Failed to commit transaction: {e}"))
                    })?;
                    self.post_query(params.group_id)?;
                    Ok(v)
                }
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    self.post_query(params.group_id)?;
                    Err(InterfaceError::Db(format!("atomic operation failed: {e}")))
                }
            }
        }
        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = is_object_owned_by_(uid, owner, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_uids_for_tags_(tags, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, StateEnumeration, Attributes)>> {
        trace!("cached sqlcipher: find: {:?}", researched_attributes);
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
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
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }
}
#[async_trait(?Send)]
impl PermissionsStore for CachedSqlCipher {
    async fn list_user_operations_granted(
        &self,
        user: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_user_granted_access_rights_(user, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_accesses_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let ret = insert_access_(uid, user, operation_types, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let ret = remove_access_(uid, user, operation_types, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        use super::sqlite::list_user_access_rights_on_object_;

        if let Some(params) = params {
            let params = <dyn SessionParams + 'static>::downcast_ref::<SqlCipherSessionParams>(
                params.as_ref(),
            );
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret =
                list_user_access_rights_on_object_(uid, user, no_inherited_access, &*pool).await;
            self.post_query(params.group_id)?;
            return Ok(ret?)
        }

        Err(InterfaceError::Db(
            "Missing group_id/key for opening SQLCipher".to_owned(),
        ))
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

impl Migrate for CachedSqlCipher {
    async fn get_db_state(&self) -> InterfaceResult<Option<DbState>> {
        todo!()
    }

    async fn set_db_state(&self, state: DbState) -> InterfaceResult<()> {
        todo!()
    }

    async fn get_current_db_version(&self) -> InterfaceResult<Option<String>> {
        todo!()
    }

    async fn set_current_db_version(&self, version: &str) -> InterfaceResult<()> {
        todo!()
    }

    async fn migrate_from_4_12_0_to_4_13_0(&self) -> InterfaceResult<()> {
        todo!()
    }

    async fn migrate_from_4_13_0_to_4_22_1(&self) -> InterfaceResult<()> {
        todo!()
    }
}

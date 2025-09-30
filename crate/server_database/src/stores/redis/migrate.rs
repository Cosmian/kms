use cosmian_logger::{debug, error};

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{DbState, KMS_VERSION_BEFORE_MIGRATION_SUPPORT},
    },
};

// We cannot implement Migrate for RedisWithFindex or else we would face the following issue:
// https://github.com/rust-lang/rust/issues/48869 because of the blanket implementation of
// Migrate for SqlDatabase
impl RedisWithFindex {
    /// Migrate the database to the latest version
    pub(crate) async fn migrate(&self) -> DbResult<()> {
        let db_state = self.get_db_state().await?.unwrap_or(DbState::Ready);
        if db_state != DbState::Ready {
            let error_string = "Database is not in a ready state; it is either upgrading or a \
                                previous upgrading failed. Bailing out. Please wait for the \
                                migration to complete or restore a previous version of the \
                                database.";
            error!("{error_string}");
            return Err(DbError::DatabaseError("error_string".to_owned()));
        }
        let current_db_version = self
            .get_current_db_version()
            .await?
            .unwrap_or_else(|| KMS_VERSION_BEFORE_MIGRATION_SUPPORT.to_owned());
        let kms_version = env!("CARGO_PKG_VERSION");
        debug!("Database version: {current_db_version}, Current KMS version: {kms_version}");

        // no migration needed for RedisWithFindex at this stage,
        // simply set the current version to the current KMS version
        if kms_version != current_db_version {
            self.set_current_db_version(kms_version).await?;
        }

        Ok(())
    }

    pub(crate) async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let state_str: Option<String> = redis::cmd("GET")
            .arg("db_state")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB state: {e}")))?;

        match state_str {
            Some(state) => Ok(Some(serde_json::from_str(&state)?)),
            None => Ok(Some(DbState::Ready)),
        }
    }

    pub(crate) async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let state_json = serde_json::to_string(&state)?;
        redis::cmd("SET")
            .arg("db_state")
            .arg(state_json)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB state: {e}")))?;

        Ok(())
    }

    pub(crate) async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let version: Option<String> = redis::cmd("GET")
            .arg("db_version")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB version: {e}")))?;

        Ok(version)
    }

    pub(crate) async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        redis::cmd("SET")
            .arg("db_version")
            .arg(version)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB version: {e}")))?;

        Ok(())
    }
}

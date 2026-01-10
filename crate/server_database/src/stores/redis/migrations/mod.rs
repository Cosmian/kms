//! This module previously contained code to migrate legacy Redis/Findex data.
//! Legacy migrations depending on `cloudproof_findex` and `redis_for_migrations` have been removed.

use async_trait::async_trait;

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{DbState, Migrate},
    },
};

#[async_trait(?Send)]
impl Migrate for RedisWithFindex {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let state_str: Option<String> = redis::cmd("GET")
            .arg("db_state")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB state: {e}")))?;

        match state_str {
            Some(state) => Ok(Some(serde_json::from_str(&state)?)),
            None => Ok(None),
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let state_json = serde_json::to_string(&state)?;
        redis::cmd("SET")
            .arg("db_state")
            .arg(state_json)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB state: {e}")))?;

        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let version: Option<String> = redis::cmd("GET")
            .arg("db_version")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB version: {e}")))?;

        Ok(version)
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        redis::cmd("SET")
            .arg("db_version")
            .arg(version)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB version: {e}")))?;

        Ok(())
    }
}

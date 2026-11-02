//! Redis migration metadata; startup retains its existing behavior until the runner is wired.

use async_trait::async_trait;

use crate::{
    DbError,
    error::DbResult,
    stores::{RedisWithFindex, migrate::DbParameters},
};

#[async_trait(?Send)]
impl DbParameters for RedisWithFindex {
    async fn get_parameter(&self, name: &str) -> DbResult<Option<String>> {
        redis::cmd("GET")
            .arg(name)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to get database parameter '{name}': {e}"))
            })
    }

    async fn set_parameter(&self, name: &str, value: &str) -> DbResult<()> {
        redis::cmd("SET")
            .arg(name)
            .arg(value)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to set database parameter '{name}': {e}"))
            })?;

        Ok(())
    }
}

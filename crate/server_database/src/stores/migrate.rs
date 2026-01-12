use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::DbResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub(crate) enum DbState {
    Ready,
    Upgrading,
}

/// Base trait for database migration functionality
#[async_trait(?Send)]
#[allow(dead_code)]
pub(crate) trait Migrate {
    /// Return the state of the database ("ready" or "upgrading").
    async fn get_db_state(&self) -> DbResult<Option<DbState>>;

    /// Set the state of the database ("ready" or "upgrading").
    async fn set_db_state(&self, state: DbState) -> DbResult<()>;

    /// Return the current version of the database.
    /// Used by the migration process to determine if the database needs to be upgraded.
    async fn get_current_db_version(&self) -> DbResult<Option<String>>;

    /// Set the current version of the database.
    /// Used by the migration process to update the database version after a successful migration.
    async fn set_current_db_version(&self, version: &str) -> DbResult<()>;
}

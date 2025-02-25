use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use version_compare::{compare, Cmp};

use crate::{InterfaceError, InterfaceResult};

pub const KMS_VERSION_BEFORE_MIGRATION_SUPPORT: &str = "4.12.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub enum DbState {
    Ready,
    Upgrading,
}

/// Trait that must implement all object stores (DBs, HSMs, etc.) that store objects
#[async_trait(?Send)]
pub trait Migrate {
    /// Migrate the database to the latest version
    async fn migrate(&self) -> InterfaceResult<()> {
        fn lower_equal(version: &str, target: &str) -> InterfaceResult<bool> {
            let cmp = compare(version, target).map_err(|()| {
                InterfaceError::Db(format!(
                    "Error comparing versions. The current DB version: {version}, cannot be \
                     parsed."
                ))
            })?;
            Ok(matches!(cmp, Cmp::Lt | Cmp::Eq))
        }

        let db_state = self.get_db_state().await?.unwrap_or(DbState::Ready);
        if db_state != DbState::Ready {
            let error_string = "Database is not in a ready state; it is either upgrading or a \
                                previous upgrading failed. Bailing out. Please wait for the \
                                migration to complete ot restore a previous version of the \
                                database.";
            error!(error_string,);
            return Err(InterfaceError::Db("error_string".to_owned()));
        }
        let current_db_version = self
            .get_current_db_version()
            .await?
            .unwrap_or(KMS_VERSION_BEFORE_MIGRATION_SUPPORT.to_owned());
        let kms_version = env!("CARGO_PKG_VERSION");
        debug!("Database version: {current_db_version}, Current KMS version: {kms_version}");

        if lower_equal(&current_db_version, "4.22.1")? {
            self.set_db_state(DbState::Upgrading).await?;
            if lower_equal(&current_db_version, KMS_VERSION_BEFORE_MIGRATION_SUPPORT)? {
                self.migrate_from_4_12_0_to_4_13_0().await?;
            }
            self.migrate_from_4_13_0_to_4_22_1().await?;
            self.set_current_db_version(kms_version).await?;
            self.set_db_state(DbState::Ready).await?;
        }

        Ok(())
    }

    /// Return the state of the database ("ready" or "upgrading").
    async fn get_db_state(&self) -> InterfaceResult<Option<DbState>>;

    /// Set the state of the database ("ready" or "upgrading").
    async fn set_db_state(&self, state: DbState) -> InterfaceResult<()>;

    /// Return the current version of the database.
    /// Used by the migration process to determine if the database needs to be upgraded.
    async fn get_current_db_version(&self) -> InterfaceResult<Option<String>>;

    /// Set the current version of the database.
    /// Used by the migration process to update the database version after a successful migration.
    async fn set_current_db_version(&self, version: &str) -> InterfaceResult<()>;

    /// Before the version 4.13.0, the KMIP attributes were stored in the object table (via the objects themselves).
    /// The new column attributes allow storing the KMIP attributes in a dedicated column
    /// even for KMIP objects that do not have KMIP attributes (such as Certificates).
    async fn migrate_from_4_12_0_to_4_13_0(&self) -> InterfaceResult<()>;

    /// Objects stored in the `objects` table have now migrated from
    /// ```json
    /// {
    ///     "object_type":"PublicKey",
    ///     "object":{
    ///         "KeyBlock":{
    ///             "KeyFormatType":"TransparentECPublicKey",
    ///             ...
    ///         }
    ///    }
    /// }
    /// ```
    /// to
    ///
    /// ```json
    /// {
    ///     "PublicKey":{
    ///         "KeyBlock":{
    ///             "KeyFormatType":"TransparentECPublicKey",
    ///             ...
    ///         }
    ///    }
    /// }
    async fn migrate_from_4_13_0_to_4_22_1(&self) -> InterfaceResult<()> {
        info!("Migrating DB to > 4.22.1");
        Ok(())
    }
}

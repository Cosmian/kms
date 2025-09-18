use async_trait::async_trait;
use cosmian_logger::{debug, error};
use serde::{Deserialize, Serialize};
use version_compare::{Cmp, compare};

use crate::{DbError, error::DbResult};

pub(super) const KMS_VERSION_BEFORE_MIGRATION_SUPPORT: &str = "4.12.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub(crate) enum DbState {
    Ready,
    Upgrading,
}

///The `Migrate` trait defines the methods required to migrate the database to the latest version.
// Note: <DB> must be present because it makes the database type a formal parameter of the trait itself.
// This solves the "unconstrained type parameter" error when trying to implement is with an sqlx generic Database
#[async_trait(?Send)]
pub(super) trait Migrate<DB> {
    /// Migrate the database to the latest version
    async fn migrate(&self) -> DbResult<()> {
        fn lower(version: &str, target: &str) -> DbResult<bool> {
            let cmp = compare(version, target).map_err(|()| {
                DbError::DatabaseError(format!(
                    "Error comparing versions. The current DB version: {version}, cannot be \
                     parsed."
                ))
            })?;
            Ok(matches!(cmp, Cmp::Lt))
        }

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

        if lower(&current_db_version, "5.0.0")? {
            let msg = format!(
                "Database version {current_db_version} cannot be upgraded to version \
                 5.0.0.\nPlease export all keys using standard formats such as PKCS#8 or Raw and \
                 reimport them in this KMS version."
            );
            error!("{}", msg);
            return Err(DbError::DatabaseError(msg));
        }

        debug!("  ==> database is up to date.");

        Ok(())
    }

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

    /// Before the version 4.13.0, the KMIP attributes were stored in the object table (via the objects themselves).
    /// The new column attributes allow storing the KMIP attributes in a dedicated column
    /// even for KMIP objects that do not have KMIP attributes (such as Certificates).
    #[expect(dead_code)]
    async fn migrate_from_4_12_0_to_4_13_0(&self) -> DbResult<()>;

    /// Objects stored in the `objects` table have now migrated from
    /// an old `DBObject` structure
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
    /// to the serialization og a KMIP 2.1 `Object`:
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
    ///
    #[expect(dead_code)]
    async fn migrate_to_4_22_2(&self) -> DbResult<()>;
}

use async_trait::async_trait;
use cosmian_logger::{debug, error};
use serde::{Deserialize, Serialize};
use version_compare::{Cmp, compare};

use crate::{DbError, error::DbResult};

pub(crate) const KMS_VERSION_BEFORE_MIGRATION_SUPPORT: &str = "4.12.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub(crate) enum DbState {
    Ready,
    Upgrading,
}

fn lower(version: &str, target: &str) -> DbResult<bool> {
    let cmp = compare(version, target).map_err(|()| {
        DbError::DatabaseError(format!(
            "Error comparing versions. The current DB version: {version}, cannot be parsed."
        ))
    })?;
    Ok(matches!(cmp, Cmp::Lt))
}

/// A marker trait to associate a database type with a store.
/// This trait's sole purpose is solving the compiler error [E0207] (`DB` is not constrained by the impl trait)
/// when trying to implement the Migrate trait for sqlx's generic Databases.
/// Avoid implementing this trait for anything that doesn't produce that error.
pub(super) trait HasDatabase {
    type Database: sqlx::Database;
}

/// Base trait for database migration functionality
#[async_trait(?Send)]
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
///The `SqlMigrate` trait defines the methods required to migrate the database to the latest version.
// Note: <DB> must be present because it makes the database type a formal parameter of the trait itself.
// This solves the "unconstrained type parameter" error when trying to implement is with an sqlx generic Database
#[async_trait(?Send)]
pub(crate) trait SqlMigrate<DB>: Migrate {
    /// Migrate the database to the latest version
    async fn migrate(&self) -> DbResult<()> {
        let db_state = self.get_db_state().await?.unwrap_or(DbState::Ready);
        if db_state != DbState::Ready {
            let error_string = "Database is not in a ready state; it is either upgrading or a \
            previous upgrading failed. Bailing out. Please wait for the \
            migration to complete or restore a previous version of the \
                                database.";
            error!("{error_string}");
            return Err(DbError::DatabaseError(error_string.to_owned()));
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
    #[expect(dead_code)]
    async fn migrate_to_4_22_2(&self) -> DbResult<()>;
}

#[cfg(feature = "non-fips")]
mod redis_migrate {
    use super::{DbError, DbResult, DbState, Migrate, debug, error, lower};
    use cloudproof_findex::Label;
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret;
    pub(crate) const LOWEST_DB_VERSION_WITH_REDIS_SUPPORT: &str = "5.0.0";

    /// Parameters specific to migrating from `cloudproof_findex_v5` to `cosmian_findex_v8`
    #[derive(Debug, Clone)]
    pub(crate) struct MigrateTo5_12_0Parameters<'a> {
        pub redis_url: String,
        pub master_key: &'a Secret<32>, // lifetime specified to avoid cloning the key
        pub label: Label,
    }
    /// Container for all migration parameters
    /// New parameters can be added here as new migrations are introduced
    #[derive(Debug, Default)]
    pub(crate) struct MigrationParams<'a> {
        /// Parameters for 5.12.0 migration (`cloudproof_findex_v5` to `cosmian_findex_v8`)
        pub(crate) migrate_to_5_12_0_parameters: Option<MigrateTo5_12_0Parameters<'a>>,
    }

    // We cannot implement SqlMigrate for RedisWithFindex or else we would face the following issue:
    // https://github.com/rust-lang/rust/issues/48869 because of the blanket implementation of
    // Migrate for SqlDatabase. Separating the migration traits is the simplest solution to this problem.
    pub(crate) trait RedisMigrate: Migrate {
        /// Migrate the database to the latest version
        async fn migrate(&self, parameters: MigrationParams<'_>) -> DbResult<()> {
            let db_state = self.get_db_state().await?;
            let current_db_version = self.get_current_db_version().await?;

            // In the absence of both, we assume the DB was constructed using a 4.5.0+ version of the KMS, up until 4.24.0
            if db_state.is_none() || current_db_version.is_none() {
                let msg = "Database state (and/or version) not set - which usually means that it was constructed with
                    a KMS version below 5.0.0. If that's the case, 
                    please export all keys using standard formats such as PKCS#8 or Raw and
                    reimport them in this KMS version.".to_owned();
                error!("{}", msg);
                return Err(DbError::DatabaseError(msg));
            }

            #[allow(clippy::unwrap_used)] // asserted it's Some() above
            let current_db_version = current_db_version.unwrap();

            if db_state != Some(DbState::Ready) {
                let error_string = "Database is not in a ready state; it is either upgrading or a \
                previous update failed. Bailing out. Please wait for the  \
                migration to complete or restore a previous version of the \
                database.";
                error!("{}", error_string,);
                return Err(DbError::DatabaseError(error_string.to_owned()));
            }

            let kms_version = env!("CARGO_PKG_VERSION");

            if kms_version == current_db_version {
                debug!("  ==> database is up to date.");
                return Ok(());
            }

            if lower(&current_db_version, LOWEST_DB_VERSION_WITH_REDIS_SUPPORT)? {
                // This case is normally unreachable and means that the db version was manually tampered-with
                let msg = format!(
                    "Databases before version {LOWEST_DB_VERSION_WITH_REDIS_SUPPORT} do not support \
                 Findex with Redis's database. Aborting. Please export all keys - if any - (using \
                 standard formats such as PKCS#8 or Raw) and reimport them using the latest KMS \
                 version."
                );
                error!("{}", msg);
                return Err(DbError::DatabaseError(msg));
            }

            // Officially start the migration process
            self.set_db_state(DbState::Upgrading).await?;

            debug!(
                "Database version before migration: {current_db_version}, Current KMS version: \
             {kms_version}, starting migration process..."
            );

            if lower(&current_db_version, "5.12.0")? {
                debug!("  ==> migrating to version 5.12.0");
                if parameters.migrate_to_5_12_0_parameters.is_none() {
                    let msg = "Missing parameters for migration to version 5.12.0. Aborting. Please \
                           provide the Redis URL, the master key and the label used by the \
                           previous DB instance.";
                    error!("{}", msg);
                    return Err(DbError::DatabaseError(msg.to_owned()));
                }
                self.migrate_to_5_12_0(parameters.migrate_to_5_12_0_parameters.ok_or_else(
                    || {
                        DbError::DatabaseError(
                            "Missing parameters for migration to version 5.12.0. Aborting. Please \
            provide the Redis URL, the master key and the label used by the \
            previous DB instance."
                                .to_owned(),
                        )
                    },
                )?)
                .await?;
                self.set_current_db_version("5.12.0").await?;
            }

            // INFO: add future migrations here if breaking changes are made to the RedisWithFindex store
            // If we reach this point, we know that kms_version is at least 5.12.0
            // simply increment the current version to the current KMS version

            if kms_version != current_db_version {
                self.set_current_db_version(kms_version).await?;
                self.set_db_state(DbState::Ready).await?;
                debug!("Redis database version was migrated to the latest version: {kms_version}");
            }

            debug!("  ==> database is up to date.");

            Ok(())
        }

        async fn migrate_to_5_12_0(&self, parameters: MigrateTo5_12_0Parameters) -> DbResult<()>;
    }
}

#[cfg(feature = "non-fips")]
pub(crate) use redis_migrate::*;

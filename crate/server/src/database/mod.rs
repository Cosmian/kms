/// This module contains the database implementation for the KMS server.
/// It provides functionality for interacting with different types of databases,
/// such as `SQLite``MySQL``PostgreSQL`eSQL, and Redis.
///
/// The module includes the following sub-modules:
/// - `cached_sqlcipher`: Contains the implementation for caching SQL queries using `SQLCipher`.
/// - `cached_sqlite_struct`: Contains the implementation for caching `SQLite` structures.
/// - `database_trait`: Contains the trait definition for a generic database.
/// - `mysql`: Contains the implementation for `MySQL` database.
/// - `object_with_metadata`: Contains the implementation for objects with metadata.
/// - `pgsql`: Contains the implementation for `PostgreSQL` database.
/// - `redis`: Contains the implementation for Redis database.
/// - `sqlite`: Contains the implementation for `SQLite` database.
/// - `locate_query`: Contains utility functions for locating queries.
/// - `migrate`: Contains functions for database migration.
/// - `retrieve_object_utils`: Contains utility functions for retrieving objects.
///
/// The module also defines the following types and constants:
/// - `KMSServer`: A type alias for the KMS server.
/// - `DBObject`: A struct representing a database object.
/// - `KMS_VERSION_BEFORE_MIGRATION_SUPPORT`: A constant representing the KMS version before migration support.
/// - `PGSQL_FILE_QUERIES`: A constant representing the `PostgreSQL` file queries.
/// - `MYSQL_FILE_QUERIES`: A constant representing the `MySQL` file queries.
/// - `SQLITE_FILE_QUERIES`: A constant representing the `SQLite` file queries.
///
/// The module also includes the following functions:
/// - `state_from_string`: Converts a string to a `StateEnumeration` value.
///
/// Finally, the module includes a test module for unit testing.
///
/// # Errors
///
/// This module does not define any specific errors. However, it may return errors
/// from the underlying database operations or from the functions defined in the sub-modules.
/// The specific error types and conditions are documented in the respective functions.
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::StateEnumeration,
};
use lazy_static::lazy_static;
use rawsql::Loader;
use serde::{Deserialize, Serialize};

use crate::{kms_bail, result::KResult};

pub type KMSServer = crate::core::KMS;

pub(crate) mod cached_sqlcipher;
pub(crate) mod cached_sqlite_struct;
mod database_trait;
pub(crate) mod mysql;
pub(crate) mod object_with_metadata;
pub(crate) mod pgsql;
pub(crate) mod redis;
pub(crate) mod sqlite;
pub(crate) use database_trait::{AtomicOperation, Database};
mod locate_query;
mod migrate;
mod retrieve_object_utils;
pub(crate) use locate_query::{
    query_from_attributes, MySqlPlaceholder, PgSqlPlaceholder, SqlitePlaceholder,
};
pub(crate) use retrieve_object_utils::retrieve_object_for_operation;

const KMS_VERSION_BEFORE_MIGRATION_SUPPORT: &str = "4.12.0";
const PGSQL_FILE_QUERIES: &str = include_str!("query.sql");
const MYSQL_FILE_QUERIES: &str = include_str!("query_mysql.sql");
const SQLITE_FILE_QUERIES: &str = include_str!("query.sql");

lazy_static! {
    static ref PGSQL_QUERIES: Loader =
        Loader::get_queries_from(PGSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref MYSQL_QUERIES: Loader =
        Loader::get_queries_from(MYSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref SQLITE_QUERIES: Loader =
        Loader::get_queries_from(SQLITE_FILE_QUERIES).expect("Can't parse the SQL file");
}

/// The Database implemented using `SQLite`
///
/// This class uses a connection should be cloned on each server thread
#[derive(Clone)]
/// When using JSON serialization, the Object is untagged
/// and looses its type information, so we have to keep
/// the `ObjectType`. See `Object` and `post_fix()` for details
#[derive(Serialize, Deserialize)]
pub(crate) struct DBObject {
    pub(crate) object_type: ObjectType,
    pub(crate) object: Object,
}

/// Converts a string to a `StateEnumeration` value.
///
/// # Errors
///
/// Returns an error if the input string does not match any valid `StateEnumeration` value.
pub fn state_from_string(s: &str) -> KResult<StateEnumeration> {
    match s {
        "PreActive" => Ok(StateEnumeration::PreActive),
        "Active" => Ok(StateEnumeration::Active),
        "Deactivated" => Ok(StateEnumeration::Deactivated),
        "Compromised" => Ok(StateEnumeration::Compromised),
        "Destroyed" => Ok(StateEnumeration::Destroyed),
        "Destroyed_Compromised" => Ok(StateEnumeration::Destroyed_Compromised),
        x => kms_bail!("invalid state in db: {}", x),
    }
}

#[cfg(test)]
mod tests;

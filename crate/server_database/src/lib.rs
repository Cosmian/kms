//! This module contains the database implementation for the KMS server.
//! It provides functionality for interacting with different types of databases,
//! such as `SQLite`, `MySQL`, `PostgreSQL`, and `Redis`.
//!
//! The module includes the following submodules:
//! - `cached_sqlcipher`: Contains the implementation for caching SQL queries using `SQLCipher`.
//! - `cached_sqlite_struct`: Contains the implementation for caching `SQLite` structures.
//! - `database_trait`: Contains the trait definition for a generic database.
//! - `mysql`: Contains the implementation for `MySQL` database.
//! - `object_with_metadata`: Contains the implementation for objects with metadata.
//! - `pgsql`: Contains the implementation for `PostgreSQL` database.
//! - `redis`: Contains the implementation for Redis database.
//! - `sqlite`: Contains the implementation for `SQLite` database.
//! - `locate_query`: Contains utility functions for locating queries.
//! - `migrate`: Contains functions for database migration.
//! - `retrieve_object_utils`: Contains utility functions for retrieving objects.
//!
//! The module also defines the following types and constants:
//! - `KMSServer`: A type alias for the KMS server.
//! - `DBObject`: A struct representing a database object.
//! - `KMS_VERSION_BEFORE_MIGRATION_SUPPORT`: A constant representing the KMS version before migration support.
//! - `PGSQL_FILE_QUERIES`: A constant representing the `PostgreSQL` file queries.
//! - `MYSQL_FILE_QUERIES`: A constant representing the `MySQL` file queries.
//! - `SQLITE_FILE_QUERIES`: A constant representing the `SQLite` file queries.
//!
//! The module also includes the following functions:
//! - `state_from_string`: Converts a string to a `StateEnumeration` value.
//!
//! Finally, the module includes a test module for unit testing.
//!
//! # Errors
//!
//! This module does not define any specific errors. However, it may return errors
//! from the underlying database operations or from the functions defined in the submodules.
//! The specific error types and conditions are documented in the respective functions.

#![deny(
    nonstandard_style,
    refining_impl_trait,
    future_incompatible,
    keyword_idents,
    let_underscore,
    unreachable_pub,
    unused,
    unsafe_code,
    clippy::all,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::pedantic,
    clippy::cargo,
    clippy::nursery,

    // restriction lints
    clippy::unwrap_used,
    clippy::get_unwrap,
    clippy::unwrap_in_result,
    clippy::assertions_on_result_states,
    clippy::panic,
    clippy::panic_in_result_fn,
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate,
    clippy::future_not_send,
    clippy::cognitive_complexity,
    clippy::significant_drop_tightening,
    clippy::iter_with_drain
)]

mod core;
pub use core::{
    AdditionalObjectStoresParams, CachedUnwrappedObject, Database, MainDbParams, UnwrappedCache,
};
mod error;
pub use error::DbError;
mod stores;
pub use stores::redis_master_key_from_password;
#[cfg(test)]
mod tests;

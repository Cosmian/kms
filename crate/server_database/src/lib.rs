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

mod core;
pub use core::{
    AdditionalObjectStoresParams, CachedUnwrappedObject, Database, MainDbParams, UnwrappedCache,
};
mod error;
pub use error::DbError;
mod stores;
#[cfg(feature = "non-fips")]
pub use stores::redis_master_key_from_password;
#[cfg(test)]
mod tests;

pub mod reexport {
    #[cfg(feature = "non-fips")]
    pub use cloudproof_findex;
    pub use cosmian_kmip;
    pub use cosmian_kms_crypto;
    pub use cosmian_kms_interfaces;
    #[cfg(feature = "non-fips")]
    pub use redis;
}

use cosmian_kmip::kmip_2_1::kmip_objects::Object;

/// Upgrades wrongly serialized `BlockCipherMode::LegacyNISTKeyWrap` (`0x8000_000D`) to
/// `BlockCipherMode::AESKeyWrapPadding` (`0x0000_000C`) for backward compatibility
/// with versions prior to 5.15.x Calling this right after deserializing ensures that no faulty
/// data even gets read from a (previously) valid database.
///
/// This function checks if the object has a `KeyWrappingData` with the legacy
/// `NISTKeyWrap` value and converts it to the correct `AESKeyWrapPadding` value.
#[allow(deprecated)] // Allow use of LegacyNISTKeyWrap for backward compatibility migration
pub(crate) fn migrate_block_cipher_mode_if_needed(mut object: Object) -> Object {
    use cosmian_kmip::{
        kmip_0::kmip_types::BlockCipherMode,
        kmip_2_1::kmip_objects::{
            Object, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey,
        },
    };
    // Only objects with key blocks can have key wrapping data
    let key_block = match &mut object {
        Object::SymmetricKey(SymmetricKey { key_block })
        | Object::PrivateKey(PrivateKey { key_block })
        | Object::PublicKey(PublicKey { key_block })
        | Object::SecretData(SecretData { key_block, .. })
        | Object::SplitKey(SplitKey { key_block, .. })
        | Object::PGPKey(PGPKey { key_block, .. }) => key_block,
        // These object types don't have key blocks
        Object::Certificate(_) | Object::CertificateRequest(_) | Object::OpaqueObject(_) => {
            return object;
        }
    };

    // Check if key_wrapping_data exists and has encryption_key_information
    if let Some(key_wrapping_data) = &mut key_block.key_wrapping_data {
        if let Some(encryption_key_info) = &mut key_wrapping_data.encryption_key_information {
            if let Some(crypto_params) = &mut encryption_key_info.cryptographic_parameters {
                if crypto_params.block_cipher_mode == Some(BlockCipherMode::LegacyNISTKeyWrap) {
                    crypto_params.block_cipher_mode = Some(BlockCipherMode::AESKeyWrapPadding);
                }
            }
        }

        // Also check MAC/signature key information (if present)
        if let Some(mac_sign_key_info) = &mut key_wrapping_data.mac_signature_key_information {
            if let Some(crypto_params) = &mut mac_sign_key_info.cryptographic_parameters {
                if crypto_params.block_cipher_mode == Some(BlockCipherMode::LegacyNISTKeyWrap) {
                    crypto_params.block_cipher_mode = Some(BlockCipherMode::AESKeyWrapPadding);
                }
            }
        }
    }

    object
}

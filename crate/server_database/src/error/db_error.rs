use std::array::TryFromSliceError;

#[cfg(feature = "non-fips")]
use cosmian_findex::Error as FindexError;
use cosmian_kmip::{
    KmipError, kmip_0::kmip_types::ErrorReason, kmip_1_4::kmip_types::ResultReason,
};
use cosmian_kms_crypto::{CryptoError, reexport::cosmian_crypto_core::CryptoCoreError};
use cosmian_kms_interfaces::InterfaceError;
use cosmian_logger::reexport::tracing;
#[cfg(feature = "non-fips")]
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, RedisMemoryError};
use thiserror::Error;

use crate::DbError::CryptographicError;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum DbError {
    // Error related to X509 Certificate
    #[error("Certificate error: {0}")]
    Certificate(String),

    // Any actions of the user that is not allowed
    #[error("REST client connection error: {0}")]
    ClientConnectionError(String),

    // Most conversion errors (UUID, UTF-8, ...). Refer to ['ConversionError'].
    #[error("Conversion Error: {0}")]
    ConversionError(#[from] ConversionDbError),

    // A failure originating from one of the cryptographic algorithms
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    // Any errors related to a bad behavior of the DB but not related to the user input
    #[error("Database Error: {0}")]
    DatabaseError(String),

    // Default error
    #[error("{0}")]
    Default(String),

    // When a user requests something, which is nonsense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // When a user requests an item which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    Kmip14Error(ResultReason, String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    Kmip21Error(ErrorReason, String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Proteccio error: {0}")]
    Proteccio(String),

    #[cfg(feature = "non-fips")]
    #[error("Redis Error: {0}")]
    Redis(#[from] redis::RedisError),

    // When a user requests an endpoint which does not exist
    #[error("Route not supported: {0}")]
    RouteNotFound(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Unexpected server error: {0}")]
    ServerError(String),

    #[error("Ext. store error: {0}")]
    Store(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // When a user requests with protection masks arg.
    #[error("This KMIP server does not yet support protection masks")]
    UnsupportedProtectionMasks,

    #[error("Invalid URL: {0}")]
    UrlError(String),

    // SQL database errors (PostgreSQL, MySQL, SQLite)
    #[error("Sql error: {0}")]
    SqlError(String),

    // When a the UnwrappedCache (LRU cache) returns an error
    #[error("Unwrapped cache error: {0}")]
    UnwrappedCache(String),

    // When the Findex's algorithm returns a non-memory related error
    #[cfg(feature = "non-fips")]
    #[error("Findex internal error: {0}")]
    Findex(#[from] FindexError<Address<ADDRESS_LENGTH>>),

    // Error related to the Redis-Memory (used underneath Findex)
    #[cfg(feature = "non-fips")]
    #[error("Redis-Memory error: {0}")]
    RedisMemory(#[from] RedisMemoryError),

    #[error("Crypto-core error: {0}")]
    CryptoCoreError(#[from] CryptoCoreError),
}

#[derive(Error, Debug)]
pub enum ConversionDbError {
    #[error("UUID conversion error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("UTF-8 conversion error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error("TryFromIntError conversion error: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("TryFromSliceError conversion error: {0}")]
    TryFromSlice(#[from] TryFromSliceError),

    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Conversion error: {0}")]
    Other(String),
}

impl From<uuid::Error> for DbError {
    fn from(e: uuid::Error) -> Self {
        Self::ConversionError(ConversionDbError::Uuid(e))
    }
}

impl From<std::string::FromUtf8Error> for DbError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::ConversionError(ConversionDbError::FromUtf8(e))
    }
}

impl From<std::num::TryFromIntError> for DbError {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(ConversionDbError::TryFromInt(e))
    }
}

impl From<TryFromSliceError> for DbError {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionError(ConversionDbError::TryFromSlice(e))
    }
}

impl From<String> for ConversionDbError {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

// SQL driver error conversions (sqlx-free)
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        let msg = e.to_string();
        // Some SQLite API misuses surface as "Query is not read-only"; in our context, this
        // most commonly happens on duplicate imports. Map to a clearer, user-facing message.
        if msg.contains("Query is not read-only") {
            Self::DatabaseError("one or more objects already exist".to_owned())
        } else {
            Self::SqlError(msg)
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<tokio_rusqlite::Error<E>> for DbError {
    fn from(e: tokio_rusqlite::Error<E>) -> Self {
        // The error type is generic across tokio-rusqlite versions; rely on string content.
        let msg = e.to_string();
        if msg.contains("Query is not read-only") {
            Self::DatabaseError("one or more objects already exist".to_owned())
        } else {
            Self::SqlError(msg)
        }
    }
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        // Normalize common constraint violations to user-friendly messages
        if let Some(db_err) = e.as_db_error() {
            use tokio_postgres::error::SqlState;
            if *db_err.code() == SqlState::UNIQUE_VIOLATION {
                return Self::DatabaseError("one or more objects already exist".to_owned());
            }
        }
        Self::SqlError(e.to_string())
    }
}

impl From<deadpool_postgres::PoolError> for DbError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        Self::SqlError(e.to_string())
    }
}

impl From<mysql_async::Error> for DbError {
    fn from(e: mysql_async::Error) -> Self {
        match e {
            mysql_async::Error::Server(ref se) => {
                // 1062 ER_DUP_ENTRY: Duplicate entry for key (unique/primary key violation)
                if se.code == 1062 {
                    return Self::DatabaseError("one or more objects already exist".to_owned());
                }
                Self::SqlError(se.to_string())
            }
            other => Self::SqlError(other.to_string()),
        }
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<tracing::dispatcher::SetGlobalDefaultError> for DbError {
    fn from(e: tracing::dispatcher::SetGlobalDefaultError) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<InterfaceError> for DbError {
    fn from(value: InterfaceError) -> Self {
        match value {
            InterfaceError::Db(s) => Self::Store(s),
            x => Self::Store(x.to_string()),
        }
    }
}

impl From<CryptoError> for DbError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Kmip(s) => Self::Kmip21Error(ErrorReason::Codec_Error, s),
            CryptoError::InvalidSize(s)
            | CryptoError::InvalidTag(s)
            | CryptoError::Derivation(s)
            | CryptoError::IndexingSlicing(s) => Self::InvalidRequest(s),
            CryptoError::ObjectNotFound(s) => Self::ItemNotFound(s),
            CryptoError::ConversionError(e)
            | CryptoError::Default(e)
            | CryptoError::NotSupported(e)
            | CryptoError::OpenSSL(e) => CryptographicError(e),
            CryptoError::Io(e) => CryptographicError(e.to_string()),
            CryptoError::SerdeJsonError(e) => CryptographicError(e.to_string()),
            #[cfg(feature = "non-fips")]
            CryptoError::Covercrypt(e) => CryptographicError(e.to_string()),
            CryptoError::TryFromSliceError(e) => CryptographicError(e.to_string()),
        }
    }
}

impl From<KmipError> for DbError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmip21Value(r, s)
            | KmipError::InvalidKmip21Object(r, s)
            | KmipError::Kmip21(r, s) => Self::Kmip21Error(r, s),
            KmipError::Kmip21NotSupported(_, s)
            | KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(e) => {
                Self::ConversionError(ConversionDbError::TryFromSlice(e))
            }
            KmipError::RegexError(s) => Self::Default(s.to_string()),
            KmipError::SerdeJsonError(e) => Self::ConversionError(ConversionDbError::SerdeJson(e)),
            KmipError::Deserialization(e) | KmipError::Serialization(e) => {
                Self::Kmip21Error(ErrorReason::Codec_Error, e)
            }
            KmipError::DeserializationSize(expected, actual) => Self::Kmip21Error(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
            KmipError::InvalidKmip14Value(result_reason, e)
            | KmipError::InvalidKmip14Object(result_reason, e)
            | KmipError::Kmip14(result_reason, e) => Self::Kmip14Error(result_reason, e),
        }
    }
}

impl From<DbError> for InterfaceError {
    fn from(value: DbError) -> Self {
        Self::Db(value.to_string())
    }
}

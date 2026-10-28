//! Shared error type for the Vault KV v2-compatible `/kv/` API routes.

use actix_web::HttpResponse;
use cosmian_kms_server_database::DbError;
use cosmian_logger::warn;
use serde_json::json;

use crate::error::KmsError;

/// Error type for the KV v2-compatible API routes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KvApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<KmsError> for KvApiError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::Unauthorized(_) => Self::Forbidden(e.to_string()),
            KmsError::ItemNotFound(_) | KmsError::Database(DbError::ItemNotFound(_)) => {
                Self::NotFound(e.to_string())
            }
            KmsError::Database(DbError::Conflict(_)) => Self::Conflict(e.to_string()),
            KmsError::NotSupported(_) => Self::BadRequest(e.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<DbError> for KvApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Unauthorized(_) => Self::Forbidden(e.to_string()),
            DbError::ItemNotFound(_) => Self::NotFound(e.to_string()),
            DbError::Conflict(_) => Self::Conflict(e.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl actix_web::error::ResponseError for KvApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, msg) = match self {
            Self::BadRequest(m) => (actix_web::http::StatusCode::BAD_REQUEST, m.clone()),
            Self::NotFound(m) => (actix_web::http::StatusCode::NOT_FOUND, m.clone()),
            Self::Conflict(m) => (actix_web::http::StatusCode::CONFLICT, m.clone()),
            Self::Forbidden(m) => (actix_web::http::StatusCode::FORBIDDEN, m.clone()),
            Self::InternalError(m) => {
                warn!("KV API internal error: {m}");
                (
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    m.clone(),
                )
            }
        };
        HttpResponse::build(status).json(json!({"errors": [msg]}))
    }
}

/// Convenience alias for KV API results.
pub(crate) type KvResult<T> = Result<T, KvApiError>;

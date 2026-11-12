//! Shared error type for the Vault KV v2-compatible `/kv/` API routes.
//!
//! Every error is returned in the Vault `{"errors": [...]}` envelope. Messages sent to clients
//! never carry internal details: a missing path and a path the caller may not use both answer
//! `403 permission denied`, and internal failures answer a generic `500` after being logged.

use actix_web::{HttpResponse, http::StatusCode};
use cosmian_kms_server_database::DbError;
use cosmian_logger::error;
use serde_json::json;

use crate::error::KmsError;

/// Error type for the KV v2-compatible API routes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KvApiError {
    /// Invalid request; the message is safe to return to the client.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// A version of a path the caller may read is absent; the message is client-safe.
    #[error("not found: {0}")]
    NotFound(String),
    /// A concurrent write won; the message is client-safe.
    #[error("conflict: {0}")]
    Conflict(String),
    /// The path does not exist or the caller may not perform the operation on it.
    #[error("permission denied")]
    Forbidden,
    /// HTTP method not supported on this route.
    #[error("unsupported operation")]
    UnsupportedOperation,
    /// Server-side failure; the detail is logged, never returned.
    #[error("internal error: {0}")]
    InternalError(String),
}

/// Message returned for every concurrent-modification conflict.
pub(crate) const CONCURRENT_UPDATE: &str = "the path was modified concurrently; retry the request";

impl From<KmsError> for KvApiError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::Unauthorized(_) => Self::Forbidden,
            KmsError::Database(db) => Self::from(db),
            KmsError::Conflict(_) => Self::Conflict(CONCURRENT_UPDATE.to_owned()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<DbError> for KvApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Unauthorized(_) => Self::Forbidden,
            DbError::Conflict(_) => Self::Conflict(CONCURRENT_UPDATE.to_owned()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl actix_web::error::ResponseError for KvApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::UnsupportedOperation => StatusCode::METHOD_NOT_ALLOWED,
            Self::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let message = match self {
            Self::BadRequest(m) | Self::NotFound(m) | Self::Conflict(m) => m.as_str(),
            Self::Forbidden => "permission denied",
            Self::UnsupportedOperation => "unsupported operation",
            Self::InternalError(detail) => {
                error!("KV API internal error: {detail}");
                "internal error"
            }
        };
        HttpResponse::build(self.status_code()).json(json!({ "errors": [message] }))
    }
}

/// Convenience alias for KV API results.
pub(crate) type KvResult<T> = Result<T, KvApiError>;

#[cfg(test)]
mod tests {
    use actix_web::{ResponseError, body::to_bytes};

    use super::*;

    #[tokio::test]
    async fn internal_details_never_reach_the_client() {
        let response = KvApiError::InternalError("db at /var/lib/kms: row 42 corrupt".to_owned())
            .error_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body())
            .await
            .expect("body is readable");
        assert_eq!(&body[..], br#"{"errors":["internal error"]}"#);
    }

    #[test]
    fn database_errors_do_not_leak_their_message() {
        let conflict = KvApiError::from(DbError::Conflict("uid 1234 owner bob".to_owned()));
        assert!(matches!(&conflict, KvApiError::Conflict(m) if m == CONCURRENT_UPDATE));
        assert!(matches!(
            KvApiError::from(KmsError::Unauthorized("uid 1234".to_owned())),
            KvApiError::Forbidden
        ));
    }
}

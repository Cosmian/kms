//! Shared error type for the Vault-compatible API routes.

use actix_web::HttpResponse;
use cosmian_logger::warn;
use serde_json::json;

use crate::error::KmsError;

/// Error type for Vault-compatible API routes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VaultApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<KmsError> for VaultApiError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::Unauthorized(_) => Self::Forbidden(e.to_string()),
            KmsError::NotSupported(_) => Self::BadRequest(e.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl actix_web::error::ResponseError for VaultApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, msg) = match self {
            Self::BadRequest(m) => (actix_web::http::StatusCode::BAD_REQUEST, m.clone()),
            Self::NotFound(m) => (actix_web::http::StatusCode::NOT_FOUND, m.clone()),
            Self::Forbidden(m) => (actix_web::http::StatusCode::FORBIDDEN, m.clone()),
            Self::InternalError(m) => {
                warn!("Vault API internal error: {m}");
                (
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    m.clone(),
                )
            }
        };
        HttpResponse::build(status).json(json!({"errors": [msg]}))
    }
}

/// Convenience alias for Vault API results.
pub(crate) type VaultResult<T> = Result<T, VaultApiError>;

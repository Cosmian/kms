//! Shared error type for the SPIRE-compatible API routes.

use actix_web::HttpResponse;
use serde_json::json;

use crate::error::KmsError;

/// Error type for SPIRE-compatible API routes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SpireApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<KmsError> for SpireApiError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::Unauthorized(_) => Self::Forbidden(e.to_string()),
            KmsError::NotSupported(_) => Self::BadRequest(e.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl actix_web::error::ResponseError for SpireApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, msg) = match self {
            Self::BadRequest(m) => (actix_web::http::StatusCode::BAD_REQUEST, m.clone()),
            Self::NotFound(m) => (actix_web::http::StatusCode::NOT_FOUND, m.clone()),
            Self::Forbidden(m) => (actix_web::http::StatusCode::FORBIDDEN, m.clone()),
            Self::InternalError(m) => {
                let (mut builder, message) = crate::routes::internal_error(
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    m,
                );
                return builder.json(json!({"errors": [message]}));
            }
        };
        HttpResponse::build(status).json(json!({"errors": [msg]}))
    }
}

/// Convenience alias for SPIRE API results.
pub(crate) type SpireResult<T> = Result<T, SpireApiError>;

#[cfg(test)]
mod tests {
    use actix_web::{ResponseError, body::to_bytes};

    use super::SpireApiError;

    #[actix_web::test]
    async fn internal_errors_hide_details() {
        let response = SpireApiError::InternalError("db at /x".to_owned()).error_response();
        assert_eq!(response.status().as_u16(), 500);
        assert!(response.headers().contains_key("x-request-id"));
        let body = to_bytes(response.into_body()).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(
            json["errors"][0]
                .as_str()
                .is_some_and(|m| m.starts_with("Internal Server Error (request id: "))
        );
        assert!(!String::from_utf8_lossy(&body).contains("db at /x"));
    }
}

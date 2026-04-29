use actix_web::{HttpResponse, HttpResponseBuilder, http::StatusCode, web::Json};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason;
use cosmian_logger::warn;
use serde::Serialize;

use crate::error::KmsError;

/// Standard JSON error body returned by all `/v1/crypto/*` endpoints.
#[derive(Debug, Serialize)]
pub(crate) struct CryptoErrorBody {
    pub(crate) error: String,
    pub(crate) description: String,
}

/// Typed error for the REST crypto API.
///
/// Maps each variant to an HTTP status code and serialises the response
/// as `{"error": "...", "description": "..."}` JSON.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoApiError {
    /// 400 — bad request input, malformed base64url, missing fields
    #[error("{0}")]
    BadRequest(String),

    /// 400 — unknown or unsupported JOSE algorithm identifier
    #[error("{0}")]
    UnsupportedAlgorithm(String),

    /// 403 — caller not authorised to use the key
    #[error("{0}")]
    Forbidden(String),

    /// 404 — KMS object UID not found
    #[error("{0}")]
    NotFound(String),

    /// 422 — crypto operation failure (wrong key type, size mismatch, etc.)
    #[error("{0}")]
    CryptoFailure(String),

    /// 500 — unexpected server error
    #[error("{0}")]
    InternalError(String),
}

impl actix_web::error::ResponseError for CryptoApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedAlgorithm(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::CryptoFailure(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let (error_code, description) = match self {
            Self::BadRequest(msg) => ("bad_request", msg.as_str()),
            Self::UnsupportedAlgorithm(msg) => ("unsupported_algorithm", msg.as_str()),
            Self::Forbidden(msg) => ("forbidden", msg.as_str()),
            Self::NotFound(msg) => ("not_found", msg.as_str()),
            Self::CryptoFailure(msg) => ("crypto_failure", msg.as_str()),
            Self::InternalError(msg) => ("internal_error", msg.as_str()),
        };

        if status >= StatusCode::INTERNAL_SERVER_ERROR {
            warn!("{status} - {description}");
        }

        let body = CryptoErrorBody {
            error: error_code.to_owned(),
            description: description.to_owned(),
        };

        HttpResponseBuilder::new(status).json(body)
    }
}

impl From<KmsError> for CryptoApiError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::Unauthorized(msg) => Self::Forbidden(msg),
            KmsError::InvalidRequest(msg) => Self::BadRequest(msg),
            KmsError::ItemNotFound(msg) => Self::NotFound(msg),
            KmsError::Kmip21Error(reason, msg) => match reason {
                ErrorReason::Item_Not_Found | ErrorReason::Object_Not_Found => Self::NotFound(msg),
                _ => Self::CryptoFailure(msg),
            },
            KmsError::CryptographicError(msg)
            | KmsError::Kmip14Error(_, msg)
            | KmsError::NotSupported(msg)
            | KmsError::InconsistentOperation(msg) => Self::CryptoFailure(msg),
            KmsError::UnsupportedAlgorithm(msg) => Self::UnsupportedAlgorithm(msg),
            KmsError::UnsupportedPlaceholder => {
                Self::BadRequest("Placeholder identifiers are not supported".to_owned())
            }
            KmsError::UnsupportedProtectionMasks => {
                Self::BadRequest("Protection masks are not supported".to_owned())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

/// Helper: decode a base64url (no-padding) string to bytes, returning `CryptoApiError::BadRequest`
/// with a descriptive message on failure.
pub(crate) fn b64_decode(field: &str, value: &str) -> Result<Vec<u8>, CryptoApiError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| {
            CryptoApiError::BadRequest(format!("Field '{field}' is not valid base64url: {e}"))
        })
}

/// Helper: encode bytes as base64url without padding.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Convenience type alias used by handler functions.
pub(crate) type CryptoResult<T> = Result<Json<T>, CryptoApiError>;

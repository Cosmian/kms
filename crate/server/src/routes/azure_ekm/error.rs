use crate::error::KmsError;
use crate::routes::azure_ekm::SUPPORTED_API_VERSIONS;
use actix_web::HttpResponse;
use actix_web::ResponseError;
use cosmian_logger::debug;
use serde::Serialize;

// If an error response is returned (with a non-200 HTTP status code), the proxy is required to
// include the following JSON body in its response.
#[derive(Serialize, Debug)]
pub(crate) struct AzureEkmErrorReply {
    // for some reason, the spec wants the code to be a string, refer to page 9...
    // due to likeliness of typos, proper constructors will be provided below
    // please keep the `code` attribute private.
    code: String,
    message: String,
}

impl From<AzureEkmErrorReply> for HttpResponse {
    fn from(e: AzureEkmErrorReply) -> Self {
        debug!("EKM Error: {:?}", e);
        // as of version 0.1-preview, the spec only returns these exact error codes
        match e.code.as_str() {
            // 400 series errors
            "InvalidRequest" | "UnsupportedApiVersion" | "UnsupportedAlgorithm" => {
                Self::BadRequest().json(e)
            }
            "Unauthorized" => Self::Unauthorized().json(e), // 401
            "Forbidden" | "KeyDisabled" | "OperationNotAllowed" => Self::Forbidden().json(e), // 403
            "KeyNotFound" => Self::NotFound().json(e),      // 404
            "TooManyRequests" => Self::TooManyRequests().json(e), // 429
            _ => Self::InternalServerError().json(e),       // 5xx errors
        }
    }
}

impl From<KmsError> for AzureEkmErrorReply {
    fn from(e: KmsError) -> Self {
        let status_code = e.status_code().as_u16();

        // Mapping non-internal errors status numeric code to an error code string
        let code = match status_code {
            400 => "InvalidRequest",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "KeyNotFound",
            429 => "TooManyRequests",
            _ => "InternalError",
        };

        Self {
            code: code.to_owned(),
            message: "An Azure EKM request to the Cosmian KMS failed".to_owned(),
        }
    }
}

// constructors for known error replies
impl AzureEkmErrorReply {
    /// API version not supported
    pub(crate) fn unsupported_api_version(version: &str) -> Self {
        Self {
            code: "UnsupportedApiVersion".to_owned(),
            message: format!(
                "API version '{version}' not supported. Supported: {SUPPORTED_API_VERSIONS:?}"
            ),
        }
    }

    /// Invalid request - malformed JSON, missing fields, invalid parameters
    pub(crate) fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: "InvalidRequest".to_owned(),
            message: message.into(),
        }
    }

    /// Algorithm not supported for this key type
    pub(crate) fn unsupported_algorithm(algorithm: &str, key_type: &str) -> Self {
        Self {
            code: "UnsupportedAlgorithm".to_owned(),
            message: format!("Algorithm '{algorithm}' is not supported for key type '{key_type}'"),
        }
    }

    /// Key not found in the External Key Management System
    pub(crate) fn key_not_found(key_name: &str) -> Self {
        Self {
            code: "KeyNotFound".to_owned(),
            message: format!("Key '{key_name}' not found",),
        }
    }

    /// Authentication failed (invalid mTLS certificate, etc.)
    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            code: "Unauthorized".to_owned(),
            message: message.into(),
        }
    }

    /// Access denied (authenticated but not authorized)
    #[allow(dead_code)] // specified so it should figure in the code, might be used later
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: "Forbidden".to_owned(),
            message: message.into(),
        }
    }

    /// Key is disabled
    #[allow(dead_code)] // specified so it should figure in the code, might be used later
    pub(crate) fn key_disabled(key_name: &str) -> Self {
        Self {
            code: "KeyDisabled".to_owned(),
            message: format!("Key '{key_name}' is disabled"),
        }
    }

    /// Operation not allowed on this key
    pub(crate) fn operation_not_allowed(operation: &str, key_name: &str) -> Self {
        Self {
            code: "OperationNotAllowed".to_owned(),
            message: format!("Operation '{operation}' is not allowed on key '{key_name}'"),
        }
    }

    /// Rate limit exceeded
    #[allow(dead_code)]
    pub(crate) fn too_many_requests() -> Self {
        Self {
            code: "TooManyRequests".to_owned(),
            message: "Too many requests. Please retry later.".to_owned(),
        }
    }

    /// Internal server error
    pub(crate) fn internal_error(message: impl Into<String>) -> Self {
        Self {
            code: "InternalError".to_owned(),
            message: message.into(),
        }
    }
}

use std::fmt;

use actix_web::{HttpResponse, ResponseError};
use cosmian_logger::debug;
use serde::Serialize;

use crate::{error::KmsError, routes::azure_ekm::SUPPORTED_API_VERSIONS};

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

impl fmt::Display for AzureEkmErrorReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
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
        // The detailed KMS error is deliberately not echoed back to the Azure caller.
        let message = "An Azure EKM request to the Cosmian KMS failed";
        // Mapping non-internal errors status numeric code to an error code string
        match status_code {
            400 => Self::invalid_request(message),
            401 => Self::unauthorized(message),
            403 => Self::forbidden(message),
            404 => Self {
                code: "KeyNotFound".to_owned(),
                message: message.to_owned(),
            },
            429 => Self::too_many_requests(),
            _ => Self::internal_error(message),
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
            message: format!("Key '{key_name}' not found"),
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
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: "Forbidden".to_owned(),
            message: message.into(),
        }
    }

    /// Key is disabled
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

    /// Internal server error
    pub(crate) fn internal_error(message: impl Into<String>) -> Self {
        Self {
            code: "InternalError".to_owned(),
            message: message.into(),
        }
    }

    /// Rate limit exceeded
    pub(crate) fn too_many_requests() -> Self {
        Self {
            code: "TooManyRequests".to_owned(),
            message: "Too many requests. Please retry later.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{body::to_bytes, http::StatusCode};

    use super::*;

    async fn status_and_body(reply: AzureEkmErrorReply) -> Option<(StatusCode, serde_json::Value)> {
        let response = HttpResponse::from(reply);
        let status = response.status();
        let bytes = to_bytes(response.into_body()).await.ok()?;
        Some((status, serde_json::from_slice(&bytes).ok()?))
    }

    #[tokio::test]
    async fn every_spec_error_code_maps_to_its_http_status_and_json_body() {
        let cases = [
            (
                AzureEkmErrorReply::invalid_request("bad"),
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "bad",
            ),
            (
                AzureEkmErrorReply::unsupported_api_version("1.0"),
                StatusCode::BAD_REQUEST,
                "UnsupportedApiVersion",
                "API version '1.0' not supported",
            ),
            (
                AzureEkmErrorReply::unsupported_algorithm("RS256", "AES"),
                StatusCode::BAD_REQUEST,
                "UnsupportedAlgorithm",
                "Algorithm 'RS256' is not supported for key type 'AES'",
            ),
            (
                AzureEkmErrorReply::unauthorized("no cert"),
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "no cert",
            ),
            (
                AzureEkmErrorReply::forbidden("denied"),
                StatusCode::FORBIDDEN,
                "Forbidden",
                "denied",
            ),
            (
                AzureEkmErrorReply::key_disabled("k1"),
                StatusCode::FORBIDDEN,
                "KeyDisabled",
                "Key 'k1' is disabled",
            ),
            (
                AzureEkmErrorReply::operation_not_allowed("wrapkey", "k1"),
                StatusCode::FORBIDDEN,
                "OperationNotAllowed",
                "Operation 'wrapkey' is not allowed on key 'k1'",
            ),
            (
                AzureEkmErrorReply::key_not_found("k1"),
                StatusCode::NOT_FOUND,
                "KeyNotFound",
                "Key 'k1' not found",
            ),
            (
                AzureEkmErrorReply::too_many_requests(),
                StatusCode::TOO_MANY_REQUESTS,
                "TooManyRequests",
                "Too many requests. Please retry later.",
            ),
            (
                AzureEkmErrorReply::internal_error("boom"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "boom",
            ),
        ];
        for (reply, expected_status, expected_code, expected_message) in cases {
            let parts = status_and_body(reply).await;
            assert_eq!(
                parts.as_ref().map(|(status, _)| *status),
                Some(expected_status),
                "status for {expected_code}"
            );
            let body = parts.map(|(_, body)| body).unwrap_or_default();
            assert_eq!(
                body.get("code").and_then(serde_json::Value::as_str),
                Some(expected_code)
            );
            assert!(
                body.get("message")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|m| m.contains(expected_message)),
                "message for {expected_code}: {body}"
            );
        }
    }

    #[test]
    fn kms_errors_map_to_azure_codes_without_leaking_details() {
        let unauthorized = AzureEkmErrorReply::from(KmsError::Unauthorized("secret detail".into()));
        assert_eq!(unauthorized.code, "Unauthorized");
        assert!(!unauthorized.message.contains("secret detail"));

        let not_found = AzureEkmErrorReply::from(KmsError::RouteNotFound("secret detail".into()));
        assert_eq!(not_found.code, "KeyNotFound");
        assert!(!not_found.message.contains("secret detail"));

        let internal = AzureEkmErrorReply::from(KmsError::Default("secret detail".into()));
        assert_eq!(internal.code, "InternalError");
        assert!(!internal.message.contains("secret detail"));
    }
}

use std::fmt::{Display, Formatter};

use actix_web::{
    // Error, HttpRequest,
    Error,
    HttpRequest,
    HttpResponse,
    ResponseError,
    // dev::ServiceResponse,
    error::JsonPayloadError,
    // middleware::ErrorHandlerResponse,
    // dev::ServiceResponse, error::JsonPayloadError, http, middleware::ErrorHandlerResponse,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason;
use cosmian_logger::debug;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::KmsError;

/// Error Name for AWS XKS Error replies
#[derive(Serialize, Deserialize, Clone)]
pub enum XksErrorName {
    /// The request was rejected because one
    /// or more input parameters is invalid.
    /// 400: ALL except `GetHealthStatus`
    #[serde(rename = "ValidationException")]
    Validation,

    /// The request was rejected because the
    /// specified external key or key store is
    /// disabled, deactivated or blocked.
    /// 400: ALL
    #[serde(rename = "InvalidStateException")]
    InvalidState,

    /// The request was rejected because the
    /// specified ciphertext, initialization vector,
    /// additional authenticated data or
    /// authentication tag is corrupted, missing,
    /// or otherwise invalid.
    /// 400: Decrypt
    #[serde(rename = "InvalidCiphertextException")]
    InvalidCiphertext,

    /// The request was rejected because the
    /// specified key does not support the
    /// requested operation.
    /// 400: Decrypt, Encrypt
    #[serde(rename = "InvalidKeyUsageException")]
    InvalidKeyUsage,

    /// The request was rejected due to
    /// invalid AWS `SigV4` signature.
    /// 401: ALL
    #[serde(rename = "AuthenticationFailedException")]
    AuthenticationFailed,

    /// The request was rejected because the
    /// operation is not authorized based on
    /// request metadata.
    /// 403: ALL except `GetHealthStatus`
    #[serde(rename = "AccessDeniedException")]
    AccessDenied,

    /// The request was rejected because the
    /// specified external key is not found.
    /// 404: ALL except `GetHealthStatus`
    #[serde(rename = "KeyNotFoundException")]
    KeyNotFound,

    /// The request was rejected because the
    /// specified URI path is not valid.
    /// 404: ALL
    #[serde(rename = "InvalidUriPathException")]
    InvalidUriPath,

    /// The request was rejected because the
    /// request rate is too high. The
    /// proxy may send this either because
    /// it is unable to keep up or the caller
    /// exceeded its request quota.
    /// 429: ALL
    #[serde(rename = "ThrottlingException")]
    Throttling,

    /// The request was rejected because the
    /// specified cryptographic operation is not
    /// implemented, or if a parameter value
    /// exceeded the maximum size that is
    /// currently supported by a specific
    /// implementation beyond the minimize size
    /// required by this API specification.
    /// 501: ALL
    #[serde(rename = "UnsupportedOperationException")]
    UnsupportedOperation,

    /// The XKS proxy timed out while trying to
    /// access a dependency layer to fulfill the
    /// request.
    /// 503: ALL
    #[serde(rename = "DependencyTimeoutException")]
    DependencyTimeout,

    /// This is a generic server error. For example,
    /// this exception is thrown due to failure of
    /// the backing key manager, or failure of a
    /// dependency layer.
    /// 500: ALL
    #[serde(rename = "InternalException")]
    Internal,
}

// Debug (and therefore `XksErrorReply`'s Display) keeps printing the AWS protocol names.
impl std::fmt::Debug for XksErrorName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Validation => "ValidationException",
            Self::InvalidState => "InvalidStateException",
            Self::InvalidCiphertext => "InvalidCiphertextException",
            Self::InvalidKeyUsage => "InvalidKeyUsageException",
            Self::AuthenticationFailed => "AuthenticationFailedException",
            Self::AccessDenied => "AccessDeniedException",
            Self::KeyNotFound => "KeyNotFoundException",
            Self::InvalidUriPath => "InvalidUriPathException",
            Self::Throttling => "ThrottlingException",
            Self::UnsupportedOperation => "UnsupportedOperationException",
            Self::DependencyTimeout => "DependencyTimeoutException",
            Self::Internal => "InternalException",
        })
    }
}

/// Error reply for AWS XKS
///
/// see: <https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md#error-codes>
///
/// Example
/// ```json
/// {
///     "errorName": "InvalidCiphertextException", // required
///     "errorMessage": "The request was rejected because the specified ciphertext, or additional authenticated data is corrupted, missing, or otherwise invalid." // optional
/// }
/// ```
#[derive(Serialize, Debug, Clone)]
#[expect(non_snake_case, reason = "AWS XKS proxy API JSON field names")]
pub struct XksErrorReply {
    pub errorName: XksErrorName,
    pub errorMessage: Option<String>,
}

impl Display for XksErrorReply {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

impl From<XksErrorReply> for HttpResponse {
    fn from(e: XksErrorReply) -> Self {
        debug!("Xks Error: {:?}", e);
        match e.errorName {
            XksErrorName::Validation
            | XksErrorName::InvalidState
            | XksErrorName::InvalidCiphertext
            | XksErrorName::InvalidKeyUsage
            | XksErrorName::AuthenticationFailed => Self::Unauthorized().json(e),
            XksErrorName::AccessDenied => Self::Forbidden().json(e),
            // We map to I am a teapot to avoid falling into the generic 404 error handler
            // and use another handler to convert it to 404
            XksErrorName::KeyNotFound => Self::ImATeapot().json(e),
            XksErrorName::InvalidUriPath => Self::NotFound().json(e),
            XksErrorName::Throttling => Self::TooManyRequests().json(e),
            XksErrorName::UnsupportedOperation => Self::NotImplemented().json(e),
            XksErrorName::DependencyTimeout => Self::ServiceUnavailable().json(e),
            XksErrorName::Internal => Self::InternalServerError().json(e),
        }
    }
}

impl ResponseError for XksErrorReply {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::from(self.clone())
    }
}

/// Map a KMS error returned by an XKS encrypt/decrypt operation to its XKS error reply.
///
/// `operation` (e.g. `"Encrypt"`) only labels the log line emitted for internal errors.
pub(crate) fn kms_error_to_xks_reply(e: KmsError, operation: &str) -> XksErrorReply {
    let (error_name, msg) = match e {
        KmsError::Unauthorized(msg)
        | KmsError::Kmip21Error(
            ErrorReason::Permission_Denied
            | ErrorReason::Invalid_Object_Type
            | ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            msg,
        ) => (XksErrorName::InvalidKeyUsage, msg),
        KmsError::ItemNotFound(msg) | KmsError::Kmip21Error(ErrorReason::Item_Not_Found, msg) => {
            (XksErrorName::KeyNotFound, msg)
        }
        // Key state errors: key is deactivated, lifecycle boundary violated, or usage denied.
        // Must be mapped to InvalidStateException (not left as HTTP 422 text/html) so that
        // AWS KMS can distinguish key-state failures from internal errors.
        KmsError::Kmip21Error(ErrorReason::Wrong_Key_Lifecycle_State, msg) => {
            (XksErrorName::InvalidState, msg)
        }
        // Usage-limit and permission errors are merged into the InvalidKeyUsageException arm above
        // Unsupported algorithm / operation
        KmsError::NotSupported(msg)
        | KmsError::UnsupportedAlgorithm(msg)
        | KmsError::Kmip21Error(
            ErrorReason::Operation_Not_Supported
            | ErrorReason::Unsupported_Cryptographic_Parameters,
            msg,
        ) => (XksErrorName::UnsupportedOperation, msg),
        // Validation / bad request errors (cryptographic errors, invalid requests, and all
        // remaining KMIP 2.1 error reasons not explicitly handled above)
        KmsError::CryptographicError(msg)
        | KmsError::InvalidRequest(msg)
        | KmsError::Kmip21Error(_, msg) => (XksErrorName::Validation, msg),
        // Everything else is an internal server error — return proper XKS JSON so AWS KMS
        // can distinguish it from InvalidStateException instead of receiving text/html.
        e => {
            info!("XKS {operation} internal error: {:?}", e);
            (XksErrorName::Internal, e.to_string())
        }
    };
    XksErrorReply {
        errorName: error_name,
        errorMessage: Some(msg),
    }
}

// Custom error handler for JSON deserialization errors
pub(crate) fn xks_json_error_handler(err: &JsonPayloadError, _req: &HttpRequest) -> Error {
    let error_message = match err {
        JsonPayloadError::Deserialize(e) => format!("JSON deserialize error: {e}"),
        _ => "Unknown error".to_owned(),
    };
    XksErrorReply {
        errorName: XksErrorName::Validation,
        errorMessage: Some(error_message),
    }
    .into()
}

pub(crate) async fn xks_path_not_found_handler(
    req: HttpRequest,
) -> Result<HttpResponse, XksErrorReply> {
    debug!("XKS Proxy - Path not found: {}", req.path());
    Err(XksErrorReply {
        errorName: XksErrorName::InvalidUriPath,
        errorMessage: Some(format!("Resource not found: {}", req.path())),
    })
}

// /// Custom error handler for "I am a teapot" which are "key not found" errors
// /// and must be reconverted to 404 to meet the spec
// pub(crate) fn xks_key_not_found_handler<B>(
//     mut service_response: ServiceResponse<B>,
// ) -> actix_web::Result<ErrorHandlerResponse<B>> {
//     *service_response.response_mut().status_mut() = http::StatusCode::NOT_FOUND;

//     // body is unchanged, map to "left" slot
//     Ok(ErrorHandlerResponse::Response(
//         service_response.map_into_left_body(),
//     ))
// }

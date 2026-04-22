#![allow(dead_code)]
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
use cosmian_logger::debug;
use serde::{Deserialize, Serialize};

/// Error Name for AWS XKS Error replies
#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
pub enum XksErrorName {
    /// The request was rejected because one
    /// or more input parameters is invalid.
    /// 400: ALL except `GetHealthStatus`
    ValidationException,

    /// The request was rejected because the
    /// specified external key or key store is
    /// disabled, deactivated or blocked.
    /// 400: ALL
    InvalidStateException,

    /// The request was rejected because the
    /// specified ciphertext, initialization vector,
    /// additional authenticated data or
    /// authentication tag is corrupted, missing,
    /// or otherwise invalid.
    /// 400: Decrypt
    InvalidCiphertextException,

    /// The request was rejected because the
    /// specified key does not support the
    /// requested operation.
    /// 400: Decrypt, Encrypt
    InvalidKeyUsageException,

    /// The request was rejected due to
    /// invalid AWS `SigV4` signature.
    /// 401: ALL
    AuthenticationFailedException,

    /// The request was rejected because the
    /// operation is not authorized based on
    /// request metadata.
    /// 403: ALL except `GetHealthStatus`
    AccessDeniedException,

    /// The request was rejected because the
    /// specified external key is not found.
    /// 404: ALL except `GetHealthStatus`
    KeyNotFoundException,

    /// The request was rejected because the
    /// specified URI path is not valid.
    /// 404: ALL
    InvalidUriPathException,

    /// The request was rejected because the
    /// request rate is too high. The
    /// proxy may send this either because
    /// it is unable to keep up or the caller
    /// exceeded its request quota.
    /// 429: ALL
    ThrottlingException,

    /// The request was rejected because the
    /// specified cryptographic operation is not
    /// implemented, or if a parameter value
    /// exceeded the maximum size that is
    /// currently supported by a specific
    /// implementation beyond the minimize size
    /// required by this API specification.
    /// 501: ALL
    UnsupportedOperationException,

    /// The XKS proxy timed out while trying to
    /// access a dependency layer to fulfill the
    /// request.
    /// 503: ALL
    DependencyTimeoutException,

    /// This is a generic server error. For example,
    /// this exception is thrown due to failure of
    /// the backing key manager, or failure of a
    /// dependency layer.
    /// 500: ALL
    InternalException,
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
#[allow(non_snake_case)]
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
            XksErrorName::ValidationException
            | XksErrorName::InvalidStateException
            | XksErrorName::InvalidCiphertextException
            | XksErrorName::InvalidKeyUsageException
            | XksErrorName::AuthenticationFailedException => Self::Unauthorized().json(e),
            XksErrorName::AccessDeniedException => Self::Forbidden().json(e),
            // We map to I am a teapot to avoid falling into the generic 404 error handler
            // and use another handler to convert it to 404
            XksErrorName::KeyNotFoundException => Self::ImATeapot().json(e),
            XksErrorName::InvalidUriPathException => Self::NotFound().json(e),
            XksErrorName::ThrottlingException => Self::TooManyRequests().json(e),
            XksErrorName::UnsupportedOperationException => Self::NotImplemented().json(e),
            XksErrorName::DependencyTimeoutException => Self::ServiceUnavailable().json(e),
            XksErrorName::InternalException => Self::InternalServerError().json(e),
        }
    }
}

impl ResponseError for XksErrorReply {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::from(self.clone())
    }
}

// Custom error handler for JSON deserialization errors
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn xks_json_error_handler(err: JsonPayloadError, _req: &HttpRequest) -> Error {
    let error_message = match &err {
        JsonPayloadError::Deserialize(e) => format!("JSON deserialize error: {e}"),
        _ => "Unknown error".to_owned(),
    };
    XksErrorReply {
        errorName: XksErrorName::ValidationException,
        errorMessage: Some(error_message),
    }
    .into()
}

pub(crate) async fn xks_path_not_found_handler(
    req: HttpRequest,
) -> Result<HttpResponse, XksErrorReply> {
    debug!("XKS Proxy - Path not found: {}", req.path());
    Err(XksErrorReply {
        errorName: XksErrorName::InvalidUriPathException,
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

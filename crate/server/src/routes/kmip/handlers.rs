use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    http::header::CONTENT_TYPE,
    post,
    web::{Bytes, Data},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        self, KmipResultHelper,
        kmip_0::{
            kmip_messages::{
                RequestMessageBatchItemVersioned, ResponseMessage,
                ResponseMessageBatchItemVersioned, ResponseMessageHeader,
            },
            kmip_types::{BlockCipherMode, ErrorReason, ProtocolVersion},
        },
        kmip_1_4::kmip_attributes::Attribute as Kmip14Attribute,
        ttlv::{
            KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, UNKNOWN_ENUMERATION, UNKNOWN_TAG,
            to_ttlv,
        },
    },
    cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::AES_128_GCM_MAC_LENGTH,
};
use cosmian_logger::{debug, error, warn};
use time::OffsetDateTime;
use tracing::Instrument;

use super::audit::{inject_audit_request, inject_response_uid};
use crate::{
    core::{
        KMS,
        operations::{
            BatchItemInput, DecodedRequestMessage, MAX_BATCH_ITEMS, decode_request_message,
            dispatch, kmip_error_response_fields, process_message,
        },
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// When an Error occurs and generating an Error Response message fails, this message is sent
/// with "Unknown Error" as the error message
const TTLV_ERROR_RESPONSE: [u8; 160] = [
    66, 0, 123, 1, 0, 0, 0, 152, 66, 0, 122, 1, 0, 0, 0, 72, 66, 0, 105, 1, 0, 0, 0, 32, 66, 0,
    106, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 66, 0, 107, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
    66, 0, 146, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0,
    0, 0, 66, 0, 15, 1, 0, 0, 0, 64, 66, 0, 127, 5, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 66, 0, 126,
    5, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 66, 0, 125, 7, 0, 0, 0, 19, 85, 110, 114, 101, 99, 111,
    118, 101, 114, 97, 98, 108, 101, 32, 101, 114, 114, 111, 114, 0, 0, 0, 0, 0,
];

/// Maximum UTF-8 byte length of an error message copied into each batch-item response.
const MAX_ERROR_MESSAGE_BYTES: usize = 512;

/// Generate a KMIP error response message in TTLV format.
fn error_response_ttlv_with_reason(
    major: i32,
    minor: i32,
    reason: ErrorReason,
    error_message: &str,
) -> TTLV {
    TTLV {
        tag: "ResponseMessage".into(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "ResponseHeader".into(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "ProtocolVersion".into(),
                        value: TTLValue::Structure(vec![
                            TTLV {
                                tag: "ProtocolVersionMajor".into(),
                                value: TTLValue::Integer(major),
                            },
                            TTLV {
                                tag: "ProtocolVersionMinor".into(),
                                value: TTLValue::Integer(minor),
                            },
                        ]),
                    },
                    TTLV {
                        tag: "TimeStamp".into(),
                        value: TTLValue::DateTime(OffsetDateTime::now_utc()),
                    },
                    TTLV {
                        tag: "BatchCount".into(),
                        value: TTLValue::Integer(1),
                    },
                ]),
            },
            TTLV {
                tag: "BatchItem".into(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "ResultStatus".into(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            value: 0x0000_0001,
                            name: "OperationFailed".into(),
                        }),
                    },
                    TTLV {
                        tag: "ResultReason".into(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            #[expect(
                                clippy::as_conversions,
                                reason = "ErrorReason has a repr(u32) KMIP wire value"
                            )]
                            value: reason as u32,
                            name: reason.to_string().into(),
                        }),
                    },
                    TTLV {
                        tag: "ResultMessage".into(),
                        value: TTLValue::TextString(error_message.to_owned()),
                    },
                ]),
            },
        ]),
    }
}

/// Generate an "Invalid Message" KMIP error response message in TTLV format.
fn error_response_ttlv(major: i32, minor: i32, error_message: &str) -> TTLV {
    error_response_ttlv_with_reason(major, minor, ErrorReason::Invalid_Message, error_message)
}

/// `Operation` and `Unique Batch Item ID` of each request batch item, read from the raw request
/// TTLV so message-level errors can echo them (KMIP 2.1 §8.6, Table 399).
fn request_batch_item_ids(
    request: Option<&TTLV>,
) -> Vec<(Option<&KmipEnumerationVariant>, Option<&[u8]>)> {
    let Some(TTLV {
        value: TTLValue::Structure(items),
        ..
    }) = request
    else {
        return vec![];
    };

    // A valid RequestMessage has one header plus no more than MAX_BATCH_ITEMS batch
    // items. Reject oversized malformed input before allocating its complete identity list.
    if items.len() > MAX_BATCH_ITEMS + 1 {
        return vec![];
    }

    items
        .iter()
        .filter(|item| &*item.tag == "BatchItem")
        .map(|item| {
            let TTLValue::Structure(children) = &item.value else {
                return (None, None);
            };
            let operation = children.iter().find_map(|child| {
                (&*child.tag == "Operation").then_some(match &child.value {
                    TTLValue::Enumeration(value) => Some(value),
                    _ => None,
                })?
            });
            let unique_batch_item_id = children.iter().find_map(|child| {
                (&*child.tag == "UniqueBatchItemID").then_some(match &child.value {
                    TTLValue::ByteString(value) => Some(value.as_slice()),
                    _ => None,
                })?
            });
            (operation, unique_batch_item_id)
        })
        .collect()
}

fn truncate_error_message(mut error_message: String) -> String {
    if error_message.len() > MAX_ERROR_MESSAGE_BYTES {
        let mut end = MAX_ERROR_MESSAGE_BYTES;
        while !error_message.is_char_boundary(end) {
            end -= 1;
        }
        error_message.truncate(end);
    }
    error_message
}

/// According to the specification, when a Request Message is invalid, the KMIP server returns a
/// Response Message containing an Operation Failed batch item for every request batch item.
/// Each item echoes its `Operation` and `Unique Batch Item ID` when specified by the request.
fn invalid_response_message_with_reason(
    major: i32,
    minor: i32,
    result_reason: ErrorReason,
    error_message: String,
    request: Option<&TTLV>,
) -> ResponseMessage {
    let error_message = truncate_error_message(error_message);

    macro_rules! error_batch_item {
        ($variant:ident, $mod:ident, $op:expr, $id:expr) => {
            ResponseMessageBatchItemVersioned::$variant(
                cosmian_kmip::$mod::kmip_messages::ResponseMessageBatchItem {
                    operation: $op.and_then(|value: &KmipEnumerationVariant| {
                        cosmian_kmip::$mod::kmip_types::OperationEnumeration::from_repr(value.value)
                            .or_else(|| value.name.parse().ok())
                    }),
                    unique_batch_item_id: $id.map(<[u8]>::to_vec),
                    result_status:
                        cosmian_kmip::kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed,
                    result_reason: Some(result_reason.into()),
                    result_message: Some(error_message.clone()),
                    asynchronous_correlation_value: None,
                    response_payload: None,
                    message_extension: None,
                },
            )
        };
    }

    let mut ids = request_batch_item_ids(request);
    if ids.is_empty() || ids.len() > MAX_BATCH_ITEMS {
        ids = vec![(None, None)];
    }
    let batch_item = ids
        .into_iter()
        .map(|(operation, unique_batch_item_id)| {
            if major >= 2 {
                error_batch_item!(V21, kmip_2_1, operation, unique_batch_item_id)
            } else {
                error_batch_item!(V14, kmip_1_4, operation, unique_batch_item_id)
            }
        })
        .collect::<Vec<_>>();

    ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
            },
            time_stamp: OffsetDateTime::now_utc(),
            batch_count: i32::try_from(batch_item.len()).unwrap_or(i32::MAX),
            ..Default::default()
        },
        batch_item,
    }
}

/// Generate KMIP JSON TTLV and send it to the KMIP server
#[post("/kmip/2_1")]
pub(crate) async fn kmip_2_1_json(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    // Only a JSON Content-Type is accepted: it makes cross-origin browser requests subject
    // to a CORS preflight, so another origin cannot submit KMIP with the user's session cookie.
    let is_json = req_http
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(KmsError::InvalidRequest(
            "POST /kmip/2_1 requires `Content-Type: application/json`".to_owned(),
        ));
    }
    let body_str =
        std::str::from_utf8(&body).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    let ttlv = serde_json::from_str::<TTLV>(body_str)?;

    let user = kms.get_user(&req_http);
    let auth_method = kms.get_auth_method(&req_http);
    debug!(target: "kmip", user = user.as_str(), ?auth_method, tag = &*ttlv.tag, "POST /kmip/2_1. Request: {:?} {}", &*ttlv.tag, user);

    let op_name = inject_audit_request(&req_http, &ttlv);

    let ttlv = Box::pin(handle_ttlv(&kms, ttlv, &user, 2, 1)).await?;

    inject_response_uid(&req_http, &ttlv, &op_name);

    // Pre-allocate buffer to avoid repeated reallocations during JSON serialization.
    // Typical KMIP responses are 300-800 bytes; 512 avoids reallocs for most responses.
    let mut buf = Vec::with_capacity(512);
    serde_json::to_writer(&mut buf, &ttlv)?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(buf))
}

/// Result reason of a request message that cannot be decoded: the spec's specific reasons for
/// an undefined tag or enumeration value, else Invalid Message (KMIP 2.1 §11.42).
fn decoding_error_reason(error_message: &str) -> ErrorReason {
    if error_message.contains(UNKNOWN_TAG) {
        ErrorReason::Unknown_Tag
    } else if error_message.contains(UNKNOWN_ENUMERATION) {
        ErrorReason::Unknown_Enumeration
    } else {
        ErrorReason::Invalid_Message
    }
}

/// Protocol versions served: the majors advertised by Discover Versions, with any minor.
/// A request with a supported major and a different minor is processed normally, ignoring
/// fields the server does not understand (KMIP 1.4 §11.1; KMIP 2.1 §9.16).
const fn is_supported_version(major: i32, minor: i32) -> bool {
    matches!(major, 1 | 2) && minor >= 0
}

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation` serialized in a single KMIP `Message`
async fn handle_ttlv(
    kms: &KMS,
    ttlv: TTLV,
    user: &UserId,
    major: i32,
    minor: i32,
) -> KResult<TTLV> {
    if &*ttlv.tag == "RequestMessage" {
        let span = tracing::span!(tracing::Level::TRACE, "message");
        let processed = match decode_request_message(&ttlv) {
            Ok(request) => Box::pin(process_message(kms, request, user))
                .instrument(span)
                .await
                .map_err(|error| kmip_error_response_fields(&error)),
            Err(error) => {
                let error_message = error.to_string();
                Err((decoding_error_reason(&error_message), error_message))
            }
        };
        let response = processed.unwrap_or_else(|(reason, error_message)| {
            let error_message = truncate_error_message(error_message);
            error!(target: "kmip", "Failed to process request: {error_message}");
            invalid_response_message_with_reason(major, minor, reason, error_message, Some(&ttlv))
        });
        let ttlv = to_ttlv(&response).unwrap_or_else(|e| {
            error!(target: "kmip", "Failed to convert response message to TTLV: {}", e);
            error_response_ttlv(major, minor, e.to_string().as_str())
        });
        Ok(ttlv)
    } else {
        let operation = dispatch(kms, ttlv, user).await?;
        Ok(to_ttlv(&operation)?)
    }
}

/// Handle KMIP requests with JSON content type
#[post("/kmip")]
pub(crate) async fn kmip(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    let content_type = req_http
        .headers()
        .get(CONTENT_TYPE)
        .context("There should be a content-type on the request")?
        .to_str()
        .map_err(|e| KmsError::InvalidRequest(format!("Cannot parse content type: {e}")))?;
    match content_type {
        "application/octet-stream" => Ok(Box::pin(kmip_binary(req_http, body, kms)).await),
        "application/json" => Ok(Box::pin(kmip_json(req_http, body, kms)).await),
        _ => Err(KmsError::InvalidRequest(format!(
            "Unsupported content type: {content_type}"
        ))),
    }
}

/// Handle KMIP requests with JSON content type
pub(crate) async fn kmip_json(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let json =
        kmip_json_inner(req_http, body, kms)
            .await
            .unwrap_or_else(|(error, (major, minor))| {
                let (reason, error_message) = kmip_error_response_fields(&error);
                let error_message = truncate_error_message(error_message);
                error!(target: "kmip", "Failed to process request: {error_message}");
                error_response_ttlv_with_reason(major, minor, reason, &error_message)
            });
    let mut buf = Vec::with_capacity(512);
    if let Err(e) = serde_json::to_writer(&mut buf, &json) {
        error!(target: "kmip", "Failed to serialize response to JSON: {e}");
        return HttpResponse::InternalServerError()
            .content_type("application/json")
            .body(r#"{"error":"internal serialization failure"}"#);
    }
    HttpResponse::Ok()
        .content_type("application/json")
        .body(buf)
}

/// Handle KMIP requests with JSON content type.
///
/// An error comes with the protocol version its error response must carry: the request
/// version when it was read, else the highest supported version.
async fn kmip_json_inner(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> Result<TTLV, (KmsError, (i32, i32))> {
    let invalid = |error: String| {
        (
            KmsError::Kmip21Error(ErrorReason::Invalid_Message, error),
            (2, 1),
        )
    };
    let user = kms.get_user(&req_http);

    // Deserialize the body directly to TTLV (avoiding intermediate Vec + Value allocations)
    let body_str = std::str::from_utf8(&body).map_err(|error| invalid(error.to_string()))?;
    let ttlv: TTLV = serde_json::from_str(body_str).map_err(|error| invalid(error.to_string()))?;
    let (major, minor) = get_kmip_version(&ttlv).map_err(|error| invalid(error.to_string()))?;

    debug!(
        target: "kmip",
        user = user.as_str(),
        tag = &*ttlv.tag,
        "POST /kmip {}.{} JSON. Request: {:?} {}", major ,minor, &*ttlv.tag, user
    );

    let op_name = inject_audit_request(&req_http, &ttlv);

    if !is_supported_version(major, minor) {
        return Err((
            KmsError::Kmip21Error(
                ErrorReason::Unsupported_Protocol_Version,
                format!(
                    "Unsupported KMIP version {major}.{minor}: the /kmip endpoint only accepts \
                     KMIP 1.x and 2.x requests"
                ),
            ),
            (major, minor),
        ));
    }
    let span = tracing::info_span!("kmip", user = user.as_str(), tag = &*ttlv.tag);
    let response_ttlv = Box::pin(handle_ttlv(&kms, ttlv, &user, major, minor))
        .instrument(span)
        .await
        .map_err(|error| (error, (major, minor)))?;

    inject_response_uid(&req_http, &response_ttlv, &op_name);

    Ok(response_ttlv)
}

/// Handle KMIP HTTP requests with binary content type
pub(crate) async fn kmip_binary(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let user = kms.get_user(&req_http);

    // Best-effort decode, done once: the request TTLV feeds both the audit hooks
    // and request processing.
    let request_ttlv = TTLV::find_version(body.as_ref())
        .ok()
        .and_then(|(major, _minor)| {
            let flavor = if major == 1 {
                KmipFlavor::Kmip1
            } else {
                KmipFlavor::Kmip2
            };
            TTLV::from_bytes(body.as_ref(), flavor).ok()
        });
    let op_name = request_ttlv
        .as_ref()
        .map(|ttlv| inject_audit_request(&req_http, ttlv));

    let (response_bytes, response_ttlv) =
        handle_ttlv_bytes_parsed(&user, body.as_ref(), request_ttlv, &kms).await;

    if let (Some(op_name), Some(response_ttlv)) = (op_name, response_ttlv) {
        inject_response_uid(&req_http, &response_ttlv, &op_name);
    }

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(response_bytes)
}

/// Handle KMIP requests in TTLV binary format
pub(crate) async fn handle_ttlv_bytes(user: &UserId, ttlv_bytes: &[u8], kms: &Arc<KMS>) -> Vec<u8> {
    handle_ttlv_bytes_parsed(user, ttlv_bytes, None, kms)
        .await
        .0
}

/// Handle KMIP requests in TTLV binary format.
///
/// `request_ttlv` is `ttlv_bytes` already decoded by the caller, if any, so it is not decoded twice.
/// Returns the response bytes and the response TTLV they encode, when one was built.
async fn handle_ttlv_bytes_parsed(
    user: &UserId,
    ttlv_bytes: &[u8],
    request_ttlv: Option<TTLV>,
    kms: &Arc<KMS>,
) -> (Vec<u8>, Option<TTLV>) {
    let (major, minor) = match TTLV::find_version(ttlv_bytes) {
        Ok(version) => version,
        // Not a KMIP request message: answer Invalid Message with the highest version served
        Err(e) => {
            return error_response_bytes(
                2,
                1,
                &KmsError::Kmip21Error(ErrorReason::Invalid_Message, e.to_string()),
                None,
            );
        }
    };
    let span = tracing::info_span!("kmip_binary", user = user.as_str());
    match handle_ttlv_bytes_inner(user, ttlv_bytes, request_ttlv, major, minor, kms)
        .instrument(span)
        .await
    {
        Ok((response_bytes, response_ttlv)) => (response_bytes, Some(response_ttlv)),
        Err(e) => {
            let flavor = if major == 1 {
                KmipFlavor::Kmip1
            } else {
                KmipFlavor::Kmip2
            };
            let request = TTLV::from_bytes(ttlv_bytes, flavor).ok();
            error_response_bytes(major, minor, &e, request.as_ref())
        }
    }
}

/// Encodes the Response Message that fails every item of a request with `error`.
fn error_response_bytes(
    major: i32,
    minor: i32,
    error: &KmsError,
    request: Option<&TTLV>,
) -> (Vec<u8>, Option<TTLV>) {
    let flavor = if major == 1 {
        KmipFlavor::Kmip1
    } else {
        KmipFlavor::Kmip2
    };
    let (reason, error_message) = kmip_error_response_fields(error);
    let error_message = truncate_error_message(error_message);
    let response_message =
        invalid_response_message_with_reason(major, minor, reason, error_message.clone(), request);
    warn!(
        target: "kmip",
        major,
        minor,
        batch_count = response_message.batch_item.len(),
        "Failed to process KMIP request: {error_message}"
    );
    let response_ttlv = to_ttlv(&response_message).unwrap_or_else(|e| {
        error!(target: "kmip", "Failed to convert response message to TTLV: {}", e);
        error_response_ttlv(major, minor, e.to_string().as_str())
    });
    match TTLV::to_bytes(&response_ttlv, flavor) {
        Ok(response_bytes) => (response_bytes, Some(response_ttlv)),
        Err(e) => {
            error!(target: "kmip", "Failed to convert Response TTLV to bytes: {e}");
            (
                TTLV_ERROR_RESPONSE.to_vec(),
                TTLV::from_bytes(&TTLV_ERROR_RESPONSE, KmipFlavor::Kmip1).ok(),
            )
        }
    }
}

async fn handle_ttlv_bytes_inner(
    user: &UserId,
    ttlv_bytes: &[u8],
    request_ttlv: Option<TTLV>,
    major: i32,
    minor: i32,
    kms: &Arc<KMS>,
) -> KResult<(Vec<u8>, TTLV)> {
    if !is_supported_version(major, minor) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Unsupported_Protocol_Version,
            format!(
                "Unsupported KMIP version {major}.{minor}: only KMIP 1.x and 2.x requests are \
                 accepted"
            ),
        ));
    }
    let kmip_flavor = if major == 1 {
        KmipFlavor::Kmip1
    } else {
        KmipFlavor::Kmip2
    };

    let ttlv = match request_ttlv {
        Some(ttlv) => ttlv,
        None => TTLV::from_bytes(ttlv_bytes, kmip_flavor).map_err(|error| {
            let error_message = format!("Failed to parse TTLV: {error}");
            KmsError::Kmip21Error(decoding_error_reason(&error_message), error_message)
        })?,
    };
    let tag = ttlv.tag.clone();
    debug!(
        target: "kmip",
        user = user.as_str(),
        tag = tag.as_ref(),
        "POST /kmip {}.{} Binary. Request: {:?} {}", major, minor, tag, user
    );

    let mut request_message = decode_request_message(&ttlv).map_err(|error| {
        let error_message = format!("Failed to parse RequestMessage: {error}");
        KmsError::Kmip21Error(decoding_error_reason(&error_message), error_message)
    })?;
    drop(ttlv);

    perform_request_tweaks(&mut request_message, major, minor);

    let mut response_message = Box::pin(process_message(kms, request_message, user)).await?;

    perform_response_tweaks(&mut response_message, major, minor);

    let response_ttlv = to_ttlv(&response_message)
        .map_err(|e| KmsError::ServerError(format!("Failed to serialize response: {e}")))?;

    let response_bytes = TTLV::to_bytes(&response_ttlv, kmip_flavor)
        .map_err(|e| KmsError::ServerError(format!("Failed to convert TTLV to bytes: {e}")))?;

    Ok((response_bytes, response_ttlv))
}

fn get_kmip_version(ttlv: &TTLV) -> KResult<(i32, i32)> {
    if &*ttlv.tag != "RequestMessage" {
        return Err(KmsError::InvalidRequest(
            "The /kmip endpoint only accepts Request messages".to_owned(),
        ));
    }
    let TTLValue::Structure(children) = &ttlv.value else {
        return Err(KmsError::InvalidRequest(
            "The /kmip endpoint only accepts Request messages".to_owned(),
        ));
    };
    let request_header = children
        .first()
        .context("The RequestMessage should have a RequestHeader")?;
    if &*request_header.tag != "RequestHeader" {
        return Err(KmsError::InvalidRequest(
            "The RequestMessage should have a RequestHeader".to_owned(),
        ));
    }
    let TTLValue::Structure(children) = &request_header.value else {
        return Err(KmsError::InvalidRequest(
            "The RequestMessage should have a RequestHeader".to_owned(),
        ));
    };
    let protocol_version = children
        .first()
        .context("The RequestMessage should have a ProtocolVersion")?;
    if &*protocol_version.tag != "ProtocolVersion" {
        return Err(KmsError::InvalidRequest(
            "The RequestMessage should have a ProtocolVersion".to_owned(),
        ));
    }
    let TTLValue::Structure(protocol_version_children) = &protocol_version.value else {
        return Err(KmsError::InvalidRequest(
            "The RequestMessage should have a ProtocolVersion".to_owned(),
        ));
    };
    let major = protocol_version_children
        .first()
        .context("The ProtocolVersion should have a major version")?;
    if &*major.tag != "ProtocolVersionMajor" {
        return Err(KmsError::InvalidRequest(
            "The ProtocolVersion should have a major version".to_owned(),
        ));
    }
    let TTLValue::Integer(major) = major.value else {
        return Err(KmsError::InvalidRequest(
            "The ProtocolVersion should have a major version".to_owned(),
        ));
    };
    let minor = protocol_version_children
        .get(1)
        .context("The ProtocolVersion should have a minor version")?;
    if &*minor.tag != "ProtocolVersionMinor" {
        return Err(KmsError::InvalidRequest(
            "The ProtocolVersion should have a minor version".to_owned(),
        ));
    }
    let TTLValue::Integer(minor) = minor.value else {
        return Err(KmsError::InvalidRequest(
            "The ProtocolVersion should have a minor version".to_owned(),
        ));
    };
    Ok((major, minor))
}

#[cfg(test)]
#[expect(clippy::expect_used)]
#[expect(clippy::unwrap_used)]
mod tests {
    use cosmian_kms_client_utils::reexport::cosmian_kmip;
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_messages::{
        ResponseMessage, ResponseMessageBatchItemVersioned,
    };
    use cosmian_logger::{info, log_init};

    #[test]
    fn invalid_response_preserves_error_reason_and_timestamp() {
        let response = super::invalid_response_message_with_reason(
            2,
            1,
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Feature_Not_Supported,
            "unsupported operation".to_owned(),
            None,
        );

        // 18262 days after the Unix epoch is 2020-01-01.
        assert!(
            response.response_header.time_stamp
                > time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(18262)
        );
        assert!(matches!(
            response.batch_item.first(),
            Some(ResponseMessageBatchItemVersioned::V21(batch_item))
                if batch_item.result_reason
                    == Some(cosmian_kmip::kmip_0::kmip_types::ErrorReason::Feature_Not_Supported)
        ));
    }

    #[test]
    fn json_error_response_preserves_protocol_reason() {
        let (reason, message) = super::kmip_error_response_fields(&super::KmsError::Kmip21Error(
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Unsupported_Protocol_Version,
            "unsupported version".to_owned(),
        ));

        assert_eq!(
            reason,
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Unsupported_Protocol_Version
        );
        assert_eq!(message, "unsupported version");

        let (reason, _) = super::kmip_error_response_fields(&super::KmsError::Kmip21Error(
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Message,
            "malformed request".to_owned(),
        ));
        assert_eq!(
            reason,
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Message
        );
    }

    #[test]
    fn error_response_ttlv_preserves_mapped_reason() -> crate::result::KResult<()> {
        let ttlv = super::error_response_ttlv_with_reason(
            2,
            1,
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Feature_Not_Supported,
            "unsupported operation",
        );
        let response: ResponseMessage = cosmian_kmip::ttlv::from_ttlv(ttlv)?;

        if !matches!(
            response.batch_item.first(),
            Some(ResponseMessageBatchItemVersioned::V21(batch_item))
                if batch_item.result_reason
                    == Some(cosmian_kmip::kmip_0::kmip_types::ErrorReason::Feature_Not_Supported)
        ) {
            return Err(super::KmsError::Default(
                "JSON error response did not preserve FeatureNotSupported".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_protocol_version_uses_protocol_reason() -> crate::result::KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let Err(err) = super::handle_ttlv_bytes_inner(
            &crate::middlewares::UserId::from("unsupported-version@example.com"),
            &[],
            None,
            3,
            0,
            &kms,
        )
        .await
        else {
            return Err(super::KmsError::Default(
                "unsupported versions must be rejected before parsing TTLV".to_owned(),
            ));
        };
        if !matches!(
            &err,
            super::KmsError::Kmip21Error(
                cosmian_kmip::kmip_0::kmip_types::ErrorReason::Unsupported_Protocol_Version,
                _
            )
        ) {
            return Err(super::KmsError::Default(format!(
                "unsupported version returned unexpected error: {err:?}"
            )));
        }
        let response = super::invalid_response_message_with_reason(
            3,
            0,
            cosmian_kmip::kmip_0::kmip_types::ErrorReason::Unsupported_Protocol_Version,
            "unsupported version".to_owned(),
            None,
        );
        if !matches!(
            response.batch_item.first(),
            Some(ResponseMessageBatchItemVersioned::V21(batch_item))
                if batch_item.result_reason
                    == Some(cosmian_kmip::kmip_0::kmip_types::ErrorReason::Unsupported_Protocol_Version)
        ) {
            return Err(super::KmsError::Default(
                "unsupported versions must use KMIP 2.x response tags".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn error_response_message() {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));
        let response = super::invalid_response_message_with_reason(
            1,
            0,
            super::ErrorReason::Invalid_Message,
            "Unknown Error".to_owned(),
            None,
        );
        assert_eq!(response.response_header.batch_count, 1);
        assert_eq!(response.batch_item.len(), 1);
        #[expect(clippy::panic)]
        let ResponseMessageBatchItemVersioned::V14(batch_item) = &response
            .batch_item
            .first()
            .expect("Expected V14 batch item")
        else {
            panic!("Expected V14 batch item");
        };
        assert_eq!(
            batch_item.result_status,
            cosmian_kmip::kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed
        );
        let ttlv = super::to_ttlv(&response).unwrap();
        info!("Response TTLV: {ttlv:?}");
        assert_eq!(ttlv.tag, "ResponseMessage");
        let bytes = super::TTLV::to_bytes(&ttlv, cosmian_kmip::ttlv::KmipFlavor::Kmip1).unwrap();
        info!("\n{:?}", &bytes);
    }

    #[test]
    fn invalid_response_caps_message_for_every_batch_item() {
        let request = super::TTLV {
            tag: "RequestMessage".into(),
            value: super::TTLValue::Structure(
                (0..super::MAX_BATCH_ITEMS)
                    .map(|index| super::TTLV {
                        tag: "BatchItem".into(),
                        value: super::TTLValue::Structure(if index == 0 {
                            vec![super::TTLV {
                                tag: "Operation".into(),
                                value: super::TTLValue::ByteString(vec![0; 1024]),
                            }]
                        } else {
                            vec![]
                        }),
                    })
                    .collect(),
            ),
        };
        let error_message = format!(
            "Expected Integer value, got: {:?}",
            super::TTLValue::ByteString(vec![0; 1024])
        );
        let response = super::invalid_response_message_with_reason(
            1,
            0,
            super::ErrorReason::Invalid_Message,
            error_message,
            Some(&request),
        );

        assert_eq!(response.batch_item.len(), super::MAX_BATCH_ITEMS);
        assert!(
            response
                .batch_item
                .iter()
                .all(|item| { matches!(item, super::ResponseMessageBatchItemVersioned::V14(_)) })
        );
        let result_message_bytes: usize = response
            .batch_item
            .iter()
            .map(|item| match item {
                super::ResponseMessageBatchItemVersioned::V14(item) => {
                    item.result_message.as_ref().map_or(0, String::len)
                }
                super::ResponseMessageBatchItemVersioned::V21(_) => 0,
            })
            .sum();
        assert!(result_message_bytes <= super::MAX_BATCH_ITEMS * super::MAX_ERROR_MESSAGE_BYTES);
    }

    #[test]
    fn invalid_response_does_not_collect_unbounded_batch_item_ids() {
        let request = super::TTLV {
            tag: "RequestMessage".into(),
            value: super::TTLValue::Structure(
                (0..=super::MAX_BATCH_ITEMS + 1)
                    .map(|_| super::TTLV {
                        tag: "BatchItem".into(),
                        value: super::TTLValue::Structure(vec![]),
                    })
                    .collect(),
            ),
        };

        assert!(super::request_batch_item_ids(Some(&request)).is_empty());
    }
}

#[expect(clippy::expect_used)]
#[cfg(test)]
mod local_tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_messages::ResponseMessage,
        ttlv::{KmipFlavor, TTLV, from_ttlv},
    };

    use super::TTLV_ERROR_RESPONSE;

    #[test]
    fn test_error_response_message_ttlv() {
        let ttlv = super::error_response_ttlv(2, 1, "error message");
        let _response: ResponseMessage = from_ttlv(ttlv).expect("Failed to parse response");
    }

    #[test]
    fn test_error_response_message_binary() {
        let ttlv = TTLV::from_bytes(&TTLV_ERROR_RESPONSE, KmipFlavor::Kmip1)
            .expect("Failed to parse response");
        let _response: ResponseMessage = from_ttlv(ttlv).expect("Failed to parse response");
    }
}

/// Perform response tweaks for KMIP 1.1 and 1.2 since we only support structures for KMIP 1.4 and 2.1
fn perform_response_tweaks(response: &mut ResponseMessage, major: i32, minor: i32) {
    if major == 1 && minor <= 2 {
        append_auth_tag_to_encrypt_response(response);
        // Located Items was introduced in KMIP 1.3
        for item in &mut response.batch_item {
            if let ResponseMessageBatchItemVersioned::V14(item) = item {
                if let Some(cosmian_kmip::kmip_1_4::kmip_operations::Operation::LocateResponse(
                    locate,
                )) = &mut item.response_payload
                {
                    locate.located_items = None;
                }
            }
        }
    }
    if major == 1 {
        strip_asymmetric_key_value_attributes(response);
        strip_kmip1_version_unsupported_attrs(response, minor);
    }
    if major == 1 && minor == 0 {
        strip_kmip_10_initial_date(response);
    }
}

/// KMIP 1.1/1.2: concatenate the AE tag into the Encrypt response `data` field,
/// because those versions have no dedicated `authenticated_encryption_tag` field.
fn append_auth_tag_to_encrypt_response(response: &mut ResponseMessage) {
    use cosmian_kmip::kmip_1_4::kmip_operations::Operation::EncryptResponse;
    for batch_item in &mut response.batch_item {
        let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
            continue;
        };
        if let Some(EncryptResponse(resp)) = item.response_payload.as_mut() {
            if let Some(auth_tag) = resp.authenticated_encryption_tag.take() {
                if let Some(data) = resp.data.as_mut() {
                    data.extend_from_slice(&auth_tag);
                }
            }
        }
    }
}

/// KMIP 1.x: strip all `KeyValue` attributes from asymmetric keys in Get responses.
/// Some KMIP 1.x clients (e.g. Veeam Backup) cannot decode the `Link` structure
/// attribute embedded in `KeyValue`; stripping it keeps the wire format compatible.
fn strip_asymmetric_key_value_attributes(response: &mut ResponseMessage) {
    use cosmian_kmip::kmip_1_4::{
        kmip_data_structures::KeyValue, kmip_objects::Object,
        kmip_operations::Operation::GetResponse,
    };
    for batch_item in &mut response.batch_item {
        let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
            continue;
        };
        let Some(GetResponse(gr)) = item.response_payload.as_mut() else {
            continue;
        };
        let is_asymmetric = matches!(&gr.object, Object::PublicKey(_) | Object::PrivateKey(_));
        if !is_asymmetric {
            continue;
        }
        if let Ok(kb) = gr.object.key_block_mut() {
            if let Some(KeyValue::Structure { attribute, .. }) = kb.key_value.as_mut() {
                *attribute = None;
            }
        }
    }
}

/// Minimum KMIP 1.x *minor* version in which `attribute` is defined by the specification.
///
/// A KMIP server SHALL NOT return an attribute that the client's protocol version does
/// not define. Sources (OASIS KMIP Specification, Section 3 "Attributes"):
/// - KMIP 1.1: `Fresh` (§3.34), `Certificate Length` (§3.9), `X.509 Certificate
///   Identifier`/`Subject`/`Issuer` (§3.10–§3.12), `Digital Signature Algorithm` (§3.16)
/// - KMIP 1.2: `Alternative Name` (§3.40), `Key Value Present` (§3.41),
///   `Key Value Location` (§3.42), `Original Creation Date` (§3.43)
/// - KMIP 1.3: `Random Number Generator` (§3.44)
/// - KMIP 1.4: `PKCS#12 Friendly Name` (§3.45), `Description` (§3.46), `Comment` (§3.47),
///   `Sensitive` (§3.48), `Always Sensitive` (§3.49), `Extractable` (§3.50),
///   `Never Extractable` (§3.51)
///
/// Everything else is available since KMIP 1.0 and therefore maps to `0`.
const fn kmip1_minor_version_introduced(attribute: &Kmip14Attribute) -> i32 {
    match attribute {
        Kmip14Attribute::CertificateLength(_)
        | Kmip14Attribute::DigitalSignatureAlgorithm(_)
        | Kmip14Attribute::Fresh(_)
        | Kmip14Attribute::X509CertificateIdentifier(_)
        | Kmip14Attribute::X509CertificateIssuer(_)
        | Kmip14Attribute::X509CertificateSubject(_) => 1,
        Kmip14Attribute::AlternativeName(_)
        | Kmip14Attribute::KeyValueLocation(_)
        | Kmip14Attribute::KeyValuePresent(_)
        | Kmip14Attribute::OriginalCreationDate(_) => 2,
        Kmip14Attribute::RandomNumberGenerator(_) => 3,
        Kmip14Attribute::AlwaysSensitive(_)
        | Kmip14Attribute::Comment(_)
        | Kmip14Attribute::Description(_)
        | Kmip14Attribute::Extractable(_)
        | Kmip14Attribute::NeverExtractable(_)
        | Kmip14Attribute::Pkcs12FriendlyName(_)
        | Kmip14Attribute::Sensitive(_) => 4,
        _ => 0,
    }
}

/// KMIP 1.x: strip every attribute that was introduced *after* the client's protocol
/// version from `Get` (inside `KeyValue`) and `GetAttributes` responses.
///
/// Returning an attribute that a pre-1.`minor` client cannot decode is a protocol
/// violation and breaks strict clients (e.g. Synology DSM, `PyKMIP`, Percona).
fn strip_kmip1_version_unsupported_attrs(response: &mut ResponseMessage, minor: i32) {
    retain_kmip1_response_attributes(response, |attribute| {
        kmip1_minor_version_introduced(attribute) <= minor
    });
}

/// KMIP 1.0: strip `Initial Date` (§3.18) from the `Get` response `KeyValue`.
///
/// This is not a specification requirement — `Initial Date` exists in KMIP 1.0 — but
/// some strict KMIP 1.0 clients (Percona) reject the encapsulated attribute.
fn strip_kmip_10_initial_date(response: &mut ResponseMessage) {
    use cosmian_kmip::kmip_1_4::{
        kmip_data_structures::KeyValue, kmip_operations::Operation::GetResponse,
    };
    for batch_item in &mut response.batch_item {
        let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
            continue;
        };
        let Some(GetResponse(gr)) = item.response_payload.as_mut() else {
            continue;
        };
        if let Ok(kb) = gr.object.key_block_mut() {
            if let Some(KeyValue::Structure { attribute, .. }) = kb.key_value.as_mut() {
                if let Some(attrs) = attribute {
                    attrs.retain(|a| !matches!(a, Kmip14Attribute::InitialDate(_)));
                    if attrs.is_empty() {
                        *attribute = None;
                    }
                }
            }
        }
    }
}

/// Apply `keep` to every attribute carried by a KMIP 1.x `Get` (inside `KeyValue`) or
/// `GetAttributes` response, dropping those for which it returns `false`.
fn retain_kmip1_response_attributes(
    response: &mut ResponseMessage,
    keep: impl Fn(&Kmip14Attribute) -> bool,
) {
    use cosmian_kmip::kmip_1_4::{
        kmip_data_structures::KeyValue,
        kmip_operations::Operation::{GetAttributesResponse, GetResponse},
    };
    for batch_item in &mut response.batch_item {
        let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
            continue;
        };
        match item.response_payload.as_mut() {
            Some(GetResponse(gr)) => {
                if let Ok(kb) = gr.object.key_block_mut() {
                    if let Some(KeyValue::Structure { attribute, .. }) = kb.key_value.as_mut() {
                        if let Some(attrs) = attribute {
                            attrs.retain(&keep);
                            if attrs.is_empty() {
                                *attribute = None;
                            }
                        }
                    }
                }
            }
            Some(GetAttributesResponse(gar)) => {
                if let Some(attrs) = gar.attribute.as_mut() {
                    attrs.retain(&keep);
                    if attrs.is_empty() {
                        gar.attribute = None;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Perform response tweaks for KMIP 1.1 and 1.2 since we only support structures for KMIP 1.4 and 2.1
fn perform_request_tweaks(request: &mut DecodedRequestMessage, major: i32, minor: i32) {
    if major == 1 && minor <= 2 {
        for batch_item in &mut request.batch_item {
            let BatchItemInput::Item(item) = batch_item else {
                continue;
            };
            let RequestMessageBatchItemVersioned::V14(item) = &mut **item else {
                continue;
            };
            if let cosmian_kmip::kmip_1_4::kmip_operations::Operation::Decrypt(decrypt) =
                &mut item.request_payload
            {
                let cryptographic_parameters =
                    decrypt.cryptographic_parameters.clone().unwrap_or_else(|| {
                        cosmian_kmip::kmip_1_4::kmip_data_structures::CryptographicParameters {
                            cryptographic_algorithm: Some(
                                cosmian_kmip::kmip_1_4::kmip_types::CryptographicAlgorithm::AES,
                            ),
                            block_cipher_mode: Some(BlockCipherMode::GCM),
                            ..Default::default()
                        }
                    });
                if cryptographic_parameters.cryptographic_algorithm.as_ref()
                    == Some(&cosmian_kmip::kmip_1_4::kmip_types::CryptographicAlgorithm::AES)
                {
                    let block_cipher_mode = cryptographic_parameters
                        .block_cipher_mode
                        .as_ref()
                        .unwrap_or(&BlockCipherMode::GCM);

                    let len = match block_cipher_mode {
                        BlockCipherMode::GCM | BlockCipherMode::GCMSIV => AES_128_GCM_MAC_LENGTH,
                        BlockCipherMode::CBC | BlockCipherMode::ECB | BlockCipherMode::XTS => 0,
                        x => {
                            warn!(
                                "Unsupported Block Cipher Mode for AES: {x:?}. The Authenticated \
                                 Encryption Tag will NOT be extracted."
                            );
                            0
                        }
                    };
                    if len > 0 {
                        if let Some(data) = &mut decrypt.data {
                            if data.len() >= len {
                                debug!(
                                    "This is a {major}.{minor} Decrypt message. Extracting \
                                     Authenticated Encryption Tag of length {len} from Data field"
                                );
                                let auth_tag = data.split_off(data.len() - len);
                                decrypt.authenticated_encryption_tag = Some(auth_tag);
                            }
                        }
                    }
                }
            }
        }
    }
}

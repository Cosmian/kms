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
                RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
                ResponseMessageBatchItemVersioned, ResponseMessageHeader,
            },
            kmip_types::{BlockCipherMode, ProtocolVersion},
        },
        ttlv::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv},
    },
    cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::AES_128_GCM_MAC_LENGTH,
};
use cosmian_logger::{debug, error, trace, warn};
use time::OffsetDateTime;
use tracing::Instrument;

use crate::{
    core::{
        KMS,
        operations::{dispatch, message},
    },
    error::KmsError,
    result::KResult,
};

use super::audit::{inject_audit_request, inject_response_uid};

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

/// Generate an "Invalid Message" KMIP error response message in TTLV format
fn error_response_ttlv(major: i32, minor: i32, error_message: &str) -> TTLV {
    TTLV {
        tag: "ResponseMessage".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "ResponseHeader".to_owned(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "ProtocolVersion".to_owned(),
                        value: TTLValue::Structure(vec![
                            TTLV {
                                tag: "ProtocolVersionMajor".to_owned(),
                                value: TTLValue::Integer(major),
                            },
                            TTLV {
                                tag: "ProtocolVersionMinor".to_owned(),
                                value: TTLValue::Integer(minor),
                            },
                        ]),
                    },
                    TTLV {
                        tag: "TimeStamp".to_owned(),
                        value: TTLValue::DateTime(OffsetDateTime::now_utc()),
                    },
                    TTLV {
                        tag: "BatchCount".to_owned(),
                        value: TTLValue::Integer(1),
                    },
                ]),
            },
            TTLV {
                tag: "BatchItem".to_owned(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "ResultStatus".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            value: 0x0000_0001,
                            name: "OperationFailed".to_owned(),
                        }),
                    },
                    TTLV {
                        tag: "ResultReason".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            value: 0x0000_0004,
                            name: "Invalid_Message".to_owned(),
                        }),
                    },
                    TTLV {
                        tag: "ResultMessage".to_owned(),
                        value: TTLValue::TextString(error_message.to_owned()),
                    },
                ]),
            },
        ]),
    }
}

/// According to the specs, when a Request Message is invalid, the KMIP server must return a
/// Response message containing a header and a Batch Item without Operation,
/// but with the Result Status field set to Operation Failed
fn invalid_response_message(major: i32, minor: i32, error_message: String) -> ResponseMessage {
    macro_rules! error_batch_item {
        ($variant:ident, $mod:ident) => {
            ResponseMessageBatchItemVersioned::$variant(
                cosmian_kmip::$mod::kmip_messages::ResponseMessageBatchItem {
                    operation: None,
                    unique_batch_item_id: None,
                    result_status:
                        cosmian_kmip::kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed,
                    result_reason: Some(
                        cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Message,
                    ),
                    result_message: Some(error_message),
                    asynchronous_correlation_value: None,
                    response_payload: None,
                    message_extension: None,
                },
            )
        };
    }

    let batch_item = if major == 2 {
        error_batch_item!(V21, kmip_2_1)
    } else {
        error_batch_item!(V14, kmip_1_4)
    };

    ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![batch_item],
    }
}

/// Generate KMIP JSON TTLV and send it to the KMIP server
#[post("/kmip/2_1")]
pub(crate) async fn kmip_2_1_json(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    let ttlv = serde_json::from_str::<TTLV>(&body)?;

    let user = kms.get_user(&req_http);
    let auth_method = kms.get_auth_method(&req_http);
    debug!(target: "kmip", user=user, ?auth_method, tag=ttlv.tag.as_str(), "POST /kmip/2_1. Request: {:?} {}", ttlv.tag.as_str(), user);

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

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation` serialized in a single KMIP `Message`
async fn handle_ttlv(kms: &KMS, ttlv: TTLV, user: &str, major: i32, minor: i32) -> KResult<TTLV> {
    if ttlv.tag.as_str() == "RequestMessage" {
        let req = match from_ttlv::<RequestMessage>(ttlv) {
            Ok(req) => req,
            Err(e) => {
                error!(target: "kmip", "Failed to parse RequestMessage: {}", e);
                return Ok(error_response_ttlv(major, minor, &e.to_string()));
            }
        };
        let span = tracing::span!(tracing::Level::TRACE, "message");
        let resp = Box::pin(message(kms, req, user))
            .instrument(span)
            .await
            .unwrap_or_else(|e| {
                error!(target: "kmip", "Failed to process request: {}", e);
                invalid_response_message(major, minor, e.to_string())
            });
        let ttlv = to_ttlv(&resp).unwrap_or_else(|e| {
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
    let json = kmip_json_inner(req_http, body, kms)
        .await
        .unwrap_or_else(|e| {
            error!(target: "kmip", "Failed to process request: {}", e);
            error_response_ttlv(2, 1, &e.to_string())
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

/// Handle KMIP requests with JSON content type
async fn kmip_json_inner(req_http: HttpRequest, body: Bytes, kms: Data<Arc<KMS>>) -> KResult<TTLV> {
    let user = kms.get_user(&req_http);

    // Deserialize the body directly to TTLV (avoiding intermediate Vec + Value allocations)
    let body_str =
        std::str::from_utf8(&body).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    let ttlv: TTLV = serde_json::from_str(body_str)?;

    let (major, minor) = get_kmip_version(&ttlv)?;

    debug!(
        target: "kmip",
        user=user,
        tag=ttlv.tag.as_str(),
        "POST /kmip {}.{} JSON. Request: {:?} {}", major ,minor, ttlv.tag.as_str(), user
    );

    let op_name = inject_audit_request(&req_http, &ttlv);

    if (major == 2 && minor == 1) || (major == 1 && minor == 4) {
        let span = tracing::info_span!("kmip", user = user.as_str(), tag = ttlv.tag.as_str());
        let response_ttlv = Box::pin(handle_ttlv(&kms, ttlv, &user, major, minor))
            .instrument(span)
            .await?;

        inject_response_uid(&req_http, &response_ttlv, &op_name);

        Ok(response_ttlv)
    } else {
        Err(KmsError::InvalidRequest(
            "The /kmip endpoint only accepts KMIP 2.1 or 1.4 requests".to_owned(),
        ))
    }
}

/// Handle KMIP HTTP requests with binary content type
pub(crate) async fn kmip_binary(
    req_http: HttpRequest,
    body: Bytes,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let user = kms.get_user(&req_http);

    // Best-effort: peek at the request TTLV to record the operation name, and
    // remember the flavor so the response can be re-parsed for `inject_response_uid`
    // below (`handle_ttlv_bytes` only returns bytes, not the response TTLV).
    let mut flavor = KmipFlavor::Kmip2;
    let mut op_name = None;
    if let Ok((major, _minor)) = TTLV::find_version(body.as_ref()) {
        flavor = if major == 1 {
            KmipFlavor::Kmip1
        } else {
            KmipFlavor::Kmip2
        };
        if let Ok(ttlv) = TTLV::from_bytes(body.as_ref(), flavor) {
            op_name = Some(inject_audit_request(&req_http, &ttlv));
        }
    }

    let response_bytes = handle_ttlv_bytes(&user, body.as_ref(), &kms).await;

    if let Some(op_name) = op_name {
        if let Ok(response_ttlv) = TTLV::from_bytes(&response_bytes, flavor) {
            inject_response_uid(&req_http, &response_ttlv, &op_name);
        }
    }

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(response_bytes)
}

/// Handle KMIP requests in TTLV binary format
pub(crate) async fn handle_ttlv_bytes(user: &str, ttlv_bytes: &[u8], kms: &Arc<KMS>) -> Vec<u8> {
    let Ok((major, minor)) = TTLV::find_version(ttlv_bytes) else {
        error!(target: "kmip", "Failed to find KMIP version");
        return vec![];
    };
    let span = tracing::info_span!("kmip_binary", user = user);
    handle_ttlv_bytes_inner(user, ttlv_bytes, major, minor, kms)
        .instrument(span)
        .await
        .unwrap_or_else(|e| {
            let response_message = invalid_response_message(major, minor, e.to_string());
            warn!(target: "kmip", "Failed to process request:\n{response_message}");
            let response_ttlv = to_ttlv(&response_message).unwrap_or_else(|e| {
                error!(target: "kmip", "Failed to convert response message to TTLV: {}", e);
                error_response_ttlv(major, minor, e.to_string().as_str())
            });
            TTLV::to_bytes(&response_ttlv, KmipFlavor::Kmip2).unwrap_or_else(|e| {
                error!(target: "kmip", "Failed to convert Response TTLV to bytes: {}: TTLV:\n{:#?}", e,response_ttlv);
                TTLV_ERROR_RESPONSE.to_vec()
            })
        })
}

async fn handle_ttlv_bytes_inner(
    user: &str,
    ttlv_bytes: &[u8],
    major: i32,
    minor: i32,
    kms: &Arc<KMS>,
) -> KResult<Vec<u8>> {
    let kmip_flavor = if major == 1 {
        KmipFlavor::Kmip1
    } else if major == 2 {
        KmipFlavor::Kmip2
    } else {
        return Err(KmsError::InvalidRequest(format!(
            "Unsupported KMIP version: {major}.{minor}",
        )));
    };

    debug!(
        target: "kmip",
        user=user,
        "Request bytes: {}",
        hex::encode(ttlv_bytes)
    );

    let ttlv = TTLV::from_bytes(ttlv_bytes, kmip_flavor).context("Failed to parse TTLV")?;
    let tag = ttlv.tag.clone();
    debug!(
        target: "kmip",
        user=user,
        tag=tag,
        "POST /kmip {}.{} Binary. Request: {:?} {}", major, minor, tag, user
    );
    debug!(
        target: "kmip",
        user=user,
        tag=tag,
        "Request TTLV: {ttlv:#?}"
    );

    let mut request_message = from_ttlv::<RequestMessage>(ttlv)
        .map_err(|e| KmsError::InvalidRequest(format!("Failed to parse RequestMessage: {e}")))?;

    perform_request_tweaks(&mut request_message, major, minor);

    trace!(
        target: "kmip",
        user=user,
        tag=tag,
        "Request Message: {request_message}"
    );

    let mut response_message = message(kms, request_message, user).await?;

    perform_response_tweaks(&mut response_message, major, minor);

    trace!(
        target: "kmip",
        user=user,
        tag=tag,
        "Response Message: {response_message}"
    );

    let response_ttlv = to_ttlv(&response_message)
        .map_err(|e| KmsError::InvalidRequest(format!("Failed to serialize response: {e}")))?;

    debug!(
        target: "kmip",
        user=user,
        tag=tag,
        "Response Message TTLV: {response_ttlv:#?}"
    );

    let response_bytes = TTLV::to_bytes(&response_ttlv, kmip_flavor)
        .map_err(|e| KmsError::InvalidRequest(format!("Failed to convert TTLV to bytes: {e}")))?;

    debug!(
        target: "kmip",
        user=user,
        tag=tag,
        "Response Message Bytes: {}", hex::encode(&response_bytes)
    );

    Ok(response_bytes)
}

fn get_kmip_version(ttlv: &TTLV) -> KResult<(i32, i32)> {
    if ttlv.tag.as_str() != "RequestMessage" {
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
    if request_header.tag.as_str() != "RequestHeader" {
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
    if protocol_version.tag.as_str() != "ProtocolVersion" {
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
    if major.tag.as_str() != "ProtocolVersionMajor" {
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
    if minor.tag.as_str() != "ProtocolVersionMinor" {
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
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_messages::ResponseMessageBatchItemVersioned;
    use cosmian_logger::{info, log_init};

    #[test]
    fn error_response_message() {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));
        let response = super::invalid_response_message(1, 0, "Unknown Error".to_owned());
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
    }
    if major == 1 {
        strip_asymmetric_key_value_attributes(response);
    }
    if major == 1 && minor == 0 {
        strip_kmip_10_unsupported_attrs(response);
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

/// KMIP 1.0: strip attributes that do not exist in that version
/// (`Fresh`, `InitialDate`) from `Get` and `GetAttributes` responses.
fn strip_kmip_10_unsupported_attrs(response: &mut ResponseMessage) {
    use cosmian_kmip::kmip_1_4::{
        kmip_attributes::Attribute,
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
                            // KMIP 1.0: Fresh does not exist; InitialDate rejected by Percona.
                            attrs.retain(|a| {
                                !matches!(a, Attribute::Fresh(_) | Attribute::InitialDate(_))
                            });
                            if attrs.is_empty() {
                                *attribute = None;
                            }
                        }
                    }
                }
            }
            Some(GetAttributesResponse(gar)) => {
                if let Some(attrs) = gar.attribute.as_mut() {
                    attrs.retain(|a| !matches!(a, Attribute::Fresh(_)));
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
fn perform_request_tweaks(response: &mut RequestMessage, major: i32, minor: i32) {
    if major == 1 && minor <= 2 {
        for batch_item in &mut response.batch_item {
            let RequestMessageBatchItemVersioned::V14(item) = batch_item else {
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

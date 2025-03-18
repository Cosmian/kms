use std::sync::Arc;

use actix_web::{
    post,
    web::{Bytes, Data, Json},
    HttpRequest, HttpResponse,
};
use cosmian_kmip::{
    kmip_2_1::kmip_messages::RequestMessage,
    ttlv::{kmip_ttlv_deserializer::from_ttlv, kmip_ttlv_serializer::to_ttlv, TTLValue, TTLV},
    KmipResultHelper,
};
use cosmian_kms_interfaces::SessionParams;
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;
use tracing::info;

use crate::{
    core::{operations::dispatch, KMS},
    error::KmsError,
    result::KResult,
};

/// Generate KMIP JSON TTLV and send it to the KMIP server
#[post("/kmip/2_1")]
pub(crate) async fn kmip_2_1_json(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<TTLV>> {
    let span = tracing::span!(tracing::Level::INFO, "kmip_2_1");
    let _enter = span.enter();

    let ttlv = serde_json::from_str::<TTLV>(&body)?;

    let user = kms.get_user(&req_http);
    info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip_2_1. Request: {:?} {}", ttlv.tag.as_str(), user);

    let ttlv = handle_ttlv_2_1(&kms, ttlv, &user, None).await?;
    Ok(Json(ttlv))
}

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation`s serialized in a single KMIP `Message`
async fn handle_ttlv_2_1(
    kms: &KMS,
    ttlv: TTLV,
    user: &str,
    database_params: Option<Arc<dyn SessionParams>>,
) -> KResult<TTLV> {
    if ttlv.tag.as_str() == "RequestMessage" {
        let req = from_ttlv::<RequestMessage>(ttlv)?;
        let resp = kms.message(req, user, database_params).await?;
        Ok(to_ttlv(&resp)?)
    } else {
        let operation = dispatch(kms, ttlv, user, database_params).await?;
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
        "application/octet-stream" => kmip_binary(req_http, body, kms),
        "application/json" => {
            let body = String::from_utf8(body.to_vec())?;
            kmip_json(req_http, body, kms)
                .await
                .map(|json| HttpResponse::Ok().json(json))
        }
        _ => Err(KmsError::InvalidRequest(format!(
            "Unsupported content type: {content_type}"
        ))),
    }
}

/// Handle KMIP requests with JSON content type
#[allow(dead_code)]
pub(crate) async fn kmip_json(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<TTLV>> {
    let span = tracing::span!(tracing::Level::DEBUG, "kmip_json");
    let _enter = span.enter();

    let value: Value = serde_json::from_str(&body)?;
    let ttlv = serde_json::from_value::<TTLV>(value)?;

    let user = kms.get_user(&req_http);
    let (major, minor) = get_kmip_version(&ttlv)?;

    info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip {}.{} JSON. Request: {:?} {}",major ,minor, ttlv.tag.as_str(), user);

    if major == 2 && minor == 1 {
        let ttlv = handle_ttlv_2_1(&kms, ttlv, &user, None).await?;
        Ok(Json(ttlv))
    } else if major == 1 && minor == 4 {
        Err(KmsError::InvalidRequest(
            "Handling of 1.4 not yet implemented".to_owned(),
        ))
    } else {
        Err(KmsError::InvalidRequest(
            "The /kmip endpoint only accepts KMIP 2.1 or 1.4 requests".to_owned(),
        ))
    }
}

/// Handle KMIP requests with binary content type
#[allow(dead_code)]
pub(crate) fn kmip_binary(
    _req_http: HttpRequest,
    _body: Bytes,
    _kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    let span = tracing::span!(tracing::Level::INFO, "kmip_binary");
    let _enter = span.enter();

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(b"OK".as_slice()))

    // let ttlv = TTLV::from_bytes(&body)?;
    // let user = kms.get_user(&req_http);
    // info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip Binary. Request: {:?} {}", ttlv.tag.as_str(), user);

    // let response_ttlv = handle_ttlv_2_1(&kms, ttlv, &user, None).await?;
    // Ok(HttpResponse::Ok()
    //     .content_type("application/octet-stream")
    //     .body(response_ttlv.to_bytes()?))
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
    info!("RequestMessage: {:?}", children);
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

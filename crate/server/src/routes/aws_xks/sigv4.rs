// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::settings::ExternalKeyStore;
use actix_web::{
    body::{Body, Bytes},
    http::Request,
    response::{IntoResponse, Response},
};
use axum::middleware::Next;
// use axum::{
//     body::{Body, Bytes},
//     http::Request,
//     response::{IntoResponse, Response},
// };
use chrono::Duration;
use lazy_static::lazy_static;
use scratchstack_aws_signature::{
    Request as Sigv4Request, SigningKey, SigningKeyKind::KSecret, sigv4_verify,
};
use std::collections::HashMap;

use crate::settings::SETTINGS;
use crate::xks_proxy::ErrorName::{AuthenticationFailedException, InternalException};
use crate::xks_proxy::XksProxyResult;
use crate::{KMS_XKS_V1_PATH, URI_PATH_PING};

lazy_static! {
    pub static ref XKSS: HashMap<&'static str, &'static ExternalKeyStore> = {
        let map: HashMap<_, _> = SETTINGS
            .external_key_stores
            .iter()
            .map(|external_key_store| {
                (
                    external_key_store.uri_path_prefix.as_str(),
                    external_key_store,
                )
            })
            .collect();
        assert_eq!(
            map.len(),
            SETTINGS.external_key_stores.len(),
            "Check configuration for duplicate uri path prefixes."
        );
        map
    };
}

// https://github.com/tokio-rs/axum/blob/main/examples/print-request-response/src/main.rs#L40-L55
// https://discord.com/channels/500028886025895936/870760546109116496/941987388979310633
pub async fn sigv4_auth(req: Request<Body>, next: Next<Body>) -> XksProxyResult<impl IntoResponse> {
    // Compute the access key id based on the URI path prefix, if any.
    let uri_path = &req.uri().path().to_owned();
    if uri_path == URI_PATH_PING {
        let res: Response = next.run(req).await;
        return Ok(res);
    }
    let (parts, body) = req.into_parts();
    let body_as_bytes: Option<Bytes> = hyper::body::to_bytes(body).await.ok();
    let body_as_vec_u8: Option<Vec<u8>> = body_as_bytes.as_ref().map(|bytes| bytes.to_vec());
    let sigv4_req = Sigv4Request::from_http_request_parts(&parts, body_as_vec_u8);
    let gsk_req = sigv4_req
        .to_get_signing_key_request(
            KSecret,
            SETTINGS.server.region.as_str(),
            SETTINGS.server.service.as_str(),
        )
        .map_err(|signature_err| {
            AuthenticationFailedException.as_axum_error(signature_err.to_string())
        })?;

    let xks = xks_by_uri_path(uri_path)?;
    if xks.sigv4_access_key_id != gsk_req.access_key {
        return Err(AuthenticationFailedException.as_axum_error(format!(
            "Access key id {} not allowed under the URI path {uri_path}",
            gsk_req.access_key
        )));
    }

    let signing_key = SigningKey {
        kind: KSecret,
        key: xks.sigv4_secret_access_key.as_str().as_bytes().to_vec(),
    };
    let allowed_mismatch = Some(Duration::minutes(5));
    if let Err(signature_error) = sigv4_verify(
        &sigv4_req,
        &signing_key,
        allowed_mismatch,
        SETTINGS.server.region.as_str(),
        SETTINGS.server.service.as_str(),
    ) {
        tracing::warn!("SigV4 failure: {signature_error}");
        return Err(AuthenticationFailedException.as_axum_error(signature_error.to_string()));
    }
    // Recompose the request as needed by the axum framework to run
    let bytes = body_as_bytes.unwrap_or_default();
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(xks.uri_path_prefix.clone());
    let res: Response = next.run(req).await;
    Ok(res)
}

fn xks_by_uri_path(uri_path: &str) -> XksProxyResult<&ExternalKeyStore> {
    if let Some(pos) = uri_path.rfind(KMS_XKS_V1_PATH) {
        let uri_path_prefix = &uri_path[0..pos];
        if let Some(xks) = XKSS.get(uri_path_prefix) {
            return Ok(xks);
        }
    }

    // Defend against a theoretically impossible condition: the request should have
    // already been rejected by the axum framework before execution ever gets here.
    Err(InternalException.as_axum_error(format!(
        "Failed to access keystore by the URI path {uri_path}"
    )))
}

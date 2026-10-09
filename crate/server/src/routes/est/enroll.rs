//! `POST /.well-known/est/simpleenroll` and `POST /.well-known/est/simplereenroll`
//! (RFC 7030 §4.2).

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    post,
    web::{Bytes, Data},
};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::scep_cms::certs_only_der;
use cosmian_logger::{info, warn};
use openssl::x509::{X509, X509Req};

use super::{base64_response, plain_response};
use crate::{
    core::KMS,
    error::KmsError,
    middlewares::PeerCertificate,
    result::KResult,
    routes::enrollment::{
        csr_matches_certificate_identity, ensure_active_certificate_of_ca, issue_from_csr,
        load_ca_chain, secrets_equal,
    },
};

/// Base64 decoder tolerant of missing padding.
static LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Content type of a successful enrollment response (RFC 7030 §4.2.3).
const CT_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";

/// Decode the PKCS#10 request body: base64 (RFC 7030 §4.2.1, RFC 5967), line breaks allowed.
/// A raw DER body (leading `SEQUENCE` byte) is tolerated from lenient clients.
fn decode_csr(body: &[u8]) -> KResult<X509Req> {
    let der = if body.first() == Some(&0x30) {
        body.to_vec()
    } else {
        let compact: Vec<u8> = body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        LENIENT_BASE64
            .decode(&compact)
            .map_err(|e| KmsError::InvalidRequest(format!("invalid base64 PKCS#10 body: {e}")))?
    };
    X509Req::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid PKCS#10 request: {e}")))
}

/// Return the validated `Authorization: Basic` credentials of the request, if any.
fn basic_credentials(req: &HttpRequest) -> Option<(String, String)> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = LENIENT_BASE64.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

fn unauthorized(basic_allowed: bool) -> HttpResponse {
    let mut response = HttpResponse::Unauthorized();
    if basic_allowed {
        response.insert_header((header::WWW_AUTHENTICATE, "Basic realm=\"EST\""));
    }
    response
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body("EST client authentication required")
}

async fn issue_and_respond(kms: &KMS, csr: &X509Req) -> KResult<HttpResponse> {
    let ca_uid = kms
        .params
        .est_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_ca_uid".to_owned()))?;
    let certificate =
        issue_from_csr(kms, ca_uid, csr, kms.params.est_template.as_ref(), None).await?;
    let der = certs_only_der(&[certificate])?;
    Ok(base64_response(CT_CERTS_ONLY, &der))
}

/// Initial enrollment (RFC 7030 §4.2.1).
///
/// Authenticated by the TLS client certificate or, when `est_require_client_cert = false`,
/// by HTTP Basic credentials checked against the configured bootstrap account.
#[post("/.well-known/est/simpleenroll")]
pub(crate) async fn post_simpleenroll(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Bytes,
) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!("POST /.well-known/est/simpleenroll ({} bytes)", body.len());

    let basic_allowed = !kms.params.est_require_client_cert
        && kms.params.est_bootstrap_username.is_some()
        && kms.params.est_bootstrap_password.is_some();
    if req.conn_data::<PeerCertificate>().is_none() {
        let authorized = basic_allowed
            && match (
                basic_credentials(&req),
                kms.params.est_bootstrap_username.as_deref(),
                kms.params.est_bootstrap_password.as_deref(),
            ) {
                (Some((user, password)), Some(expected_user), Some(expected_password)) => {
                    // Evaluate both comparisons before combining, to avoid a timing oracle
                    // on which one failed.
                    let user_ok = secrets_equal(&user, expected_user);
                    let password_ok = secrets_equal(&password, expected_password);
                    user_ok & password_ok
                }
                _ => false,
            };
        if !authorized {
            warn!("EST simpleenroll rejected: no valid client authentication");
            return Ok(unauthorized(basic_allowed));
        }
    }

    let csr = decode_csr(&body)?;
    issue_and_respond(&kms, &csr).await
}

/// Re-enrollment core (RFC 7030 §4.2.2): `peer` is the TLS client certificate being renewed,
/// which must have been issued by the EST CA and still be active.
pub(crate) async fn simple_reenroll(
    kms: &KMS,
    peer: Option<&X509>,
    body: &[u8],
) -> KResult<HttpResponse> {
    let Some(peer) = peer else {
        return Ok(unauthorized(false));
    };
    let ca_uid = kms
        .params
        .est_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_ca_uid".to_owned()))?;
    let chain = load_ca_chain(kms, ca_uid).await?;
    let ca_cert = chain
        .first()
        .ok_or_else(|| KmsError::ServerError("EST CA certificate chain is empty".to_owned()))?;
    if let Err(e) = ensure_active_certificate_of_ca(kms, ca_uid, ca_cert, peer).await {
        warn!("EST simplereenroll rejected: {e}");
        return Ok(plain_response(StatusCode::FORBIDDEN, &e.to_string()));
    }

    let csr = decode_csr(body)?;
    // RFC 7030 §4.2.2: Subject and SubjectAltName MUST be identical to the certificate
    // being renewed.
    if !csr_matches_certificate_identity(&csr, peer)? {
        return Ok(plain_response(
            StatusCode::BAD_REQUEST,
            "the CSR Subject and SubjectAltName must be identical to those of the certificate \
             being renewed (RFC 7030 §4.2.2)",
        ));
    }
    issue_and_respond(kms, &csr).await
}

/// Re-enrollment (RFC 7030 §4.2.2): always authenticated by the TLS client certificate being
/// renewed.
#[post("/.well-known/est/simplereenroll")]
pub(crate) async fn post_simplereenroll(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Bytes,
) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!(
        "POST /.well-known/est/simplereenroll ({} bytes)",
        body.len()
    );
    let peer = req.conn_data::<PeerCertificate>().map(|p| p.cert.clone());
    simple_reenroll(&kms, peer.as_ref(), &body).await
}

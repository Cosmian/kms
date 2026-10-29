//! `POST /.well-known/est/simpleenroll` and `POST /.well-known/est/simplereenroll`
//! (RFC 7030 §4.2).

use std::{sync::Arc, time::Instant};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    post,
    web::{Data, Payload},
};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::{
    csr_attrs::{csr_challenge_password, csr_has_challenge_password},
    scep_cms::certs_only_der,
};
use cosmian_logger::{info, warn};
use openssl::x509::{X509, X509Req};

use super::{base64_response, plain_response};
use crate::{
    core::KMS,
    error::KmsError,
    middlewares::{PeerCertificate, TlsUnique, is_enrollment_issued},
    result::KResult,
    routes::enrollment::{
        EnrollmentOutcome, audit_enrollment_result, busy_response, client_ip,
        csr_matches_certificate_identity, ensure_active_certificate_of_ca, is_issued_by,
        issue_from_csr, load_ca_chain, locked_response, read_limited_body, secrets_equal,
        subject_cn,
    },
};

/// Operation names recorded in the audit trail.
const OP_SIMPLEENROLL: &str = "EstSimpleEnroll";
const OP_SIMPLEREENROLL: &str = "EstSimpleReenroll";

/// The client certificate is refused with this fixed text; the reason (certificate UID, state,
/// issuer) only goes to the log.
const CERTIFICATE_REFUSED: &str = "this client certificate cannot be used for enrollment";

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

/// RFC 7030 §3.5: a CSR `challengePassword` carries base64(tls-unique) of the client's TLS
/// connection, which the server MUST verify. `tls_unique` is the binding of the current
/// connection (`None` when undefined, e.g. TLS 1.3). `Err` holds the client-facing reason.
fn check_tls_unique(csr: &X509Req, tls_unique: Option<&[u8]>) -> Result<(), &'static str> {
    if !csr_has_challenge_password(csr) {
        return Ok(());
    }
    let Some(binding) = tls_unique else {
        return Err(
            "the CSR challengePassword (tls-unique) cannot be verified: this connection has no \
             tls-unique channel binding (TLS 1.2 is required)",
        );
    };
    match csr_challenge_password(csr) {
        Some(supplied) if secrets_equal(&supplied, &STANDARD.encode(binding)) => Ok(()),
        _ => Err(
            "the CSR challengePassword does not match the tls-unique value of this TLS \
                  connection",
        ),
    }
}

/// The `tls-unique` channel binding of the request's TLS connection, if any.
fn connection_tls_unique(req: &HttpRequest) -> Option<Vec<u8>> {
    req.conn_data::<TlsUnique>().map(|t| t.0.clone())
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
        .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .body("EST client authentication required")
}

/// Result of checking the HTTP Basic bootstrap credentials of a request.
enum BasicLogin {
    /// Basic bootstrap is disabled or the request carries no credentials (an RFC 7030 client
    /// first sends the request without them and waits for the 401 challenge: not a guess).
    Absent,
    /// Credentials were supplied and are wrong.
    Wrong,
    Valid,
}

fn check_basic(kms: &KMS, req: &HttpRequest) -> BasicLogin {
    let (Some(expected_user), Some(expected_password), false) = (
        kms.params.est_bootstrap_username.as_deref(),
        kms.params.est_bootstrap_password.as_deref(),
        kms.params.est_require_client_cert,
    ) else {
        return BasicLogin::Absent;
    };
    let Some((user, password)) = basic_credentials(req) else {
        return BasicLogin::Absent;
    };
    // Evaluate both comparisons before combining, to avoid a timing oracle on which one failed.
    let user_ok = secrets_equal(&user, expected_user);
    let password_ok = secrets_equal(&password, expected_password);
    if user_ok & password_ok {
        BasicLogin::Valid
    } else {
        BasicLogin::Wrong
    }
}

async fn issue_and_respond(kms: &KMS, csr: &X509Req) -> KResult<HttpResponse> {
    let ca_uid = kms
        .params
        .est_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_ca_uid".to_owned()))?;
    let template = kms
        .params
        .est_template
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_template".to_owned()))?;
    let issued = issue_from_csr(kms, ca_uid, csr, template).await?;
    let der = certs_only_der(&[issued.certificate])?;
    let mut response = base64_response(CT_CERTS_ONLY, &der);
    response
        .extensions_mut()
        .insert(EnrollmentOutcome(Ok(issued.uid)));
    Ok(response)
}

/// Initial enrollment (RFC 7030 §4.2.1).
///
/// Authenticated by the TLS client certificate or, when `est_require_client_cert = false`,
/// by HTTP Basic credentials checked against the configured bootstrap account. Repeated wrong
/// credentials lock the client out for a growing delay.
#[post("/.well-known/est/simpleenroll")]
pub(crate) async fn post_simpleenroll(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    payload: Payload,
) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    let started = Instant::now();
    let client = client_ip(&kms, &req);
    info!("POST /.well-known/est/simpleenroll from {client}");

    let peer = req.conn_data::<PeerCertificate>().map(|p| p.cert.clone());
    let principal = if let Some(peer) = &peer {
        format!("est-mtls:{}", subject_cn(peer))
    } else {
        // The lockout only guards the guessable Basic password: a client certificate cannot
        // be guessed, so failures from a shared address must not block mutual-TLS clients.
        if let Some(wait) = kms.enrollment_guard.locked_for(client) {
            warn!("EST simpleenroll refused: {client} is locked out");
            return Ok(locked_response(wait));
        }
        match check_basic(&kms, &req) {
            BasicLogin::Valid => {
                kms.enrollment_guard.record_success(client);
                format!(
                    "est-basic:{}",
                    kms.params.est_bootstrap_username.as_deref().unwrap_or("")
                )
            }
            login => {
                if matches!(login, BasicLogin::Wrong) {
                    kms.enrollment_guard.record_failure(client);
                }
                let basic_allowed = !kms.params.est_require_client_cert
                    && kms.params.est_bootstrap_username.is_some()
                    && kms.params.est_bootstrap_password.is_some();
                audit_enrollment_result(
                    &kms,
                    OP_SIMPLEENROLL,
                    "unauthenticated",
                    client,
                    started,
                    &Ok(unauthorized(basic_allowed)),
                );
                return Ok(unauthorized(basic_allowed));
            }
        }
    };

    let Some(_permit) = kms.enrollment_guard.try_begin() else {
        return Ok(busy_response());
    };
    let body = match read_limited_body(payload).await {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    let tls_unique = connection_tls_unique(&req);
    let result = async {
        let csr = decode_csr(&body)?;
        if let Err(reason) = check_tls_unique(&csr, tls_unique.as_deref()) {
            warn!("EST simpleenroll rejected: {reason}");
            return Ok(plain_response(StatusCode::BAD_REQUEST, reason));
        }
        enroll_for_peer(&kms, peer.as_ref(), &csr).await
    }
    .await;
    audit_enrollment_result(&kms, OP_SIMPLEENROLL, &principal, client, started, &result);
    result
}

/// Issue for an authenticated request. A client certificate issued by the EST CA must still be
/// active (TLS verification does not check revocation) and may only be re-enrolled for the
/// same Subject/SubjectAltName, so it cannot be used to obtain another identity. Any other
/// certificate that carries the enrollment marker (SCEP-enrolled, or issued by a previous key of
/// the EST CA) is refused: its state cannot be checked here and it must renew where it was
/// issued.
pub(crate) async fn enroll_for_peer(
    kms: &KMS,
    peer: Option<&X509>,
    csr: &X509Req,
) -> KResult<HttpResponse> {
    if let Some(peer) = peer {
        let ca_uid =
            kms.params.est_ca_uid.as_deref().ok_or_else(|| {
                KmsError::ServerError("EST enabled without est_ca_uid".to_owned())
            })?;
        let chain = load_ca_chain(kms, ca_uid).await?;
        let issued_by_est_ca = match chain.first() {
            Some(ca_cert) => is_issued_by(peer, ca_cert)?,
            None => false,
        };
        if issued_by_est_ca {
            if let Some(ca_cert) = chain.first() {
                if let Err(e) = ensure_active_certificate_of_ca(kms, ca_uid, ca_cert, peer).await {
                    warn!("EST simpleenroll rejected: {e}");
                    return Ok(plain_response(StatusCode::FORBIDDEN, CERTIFICATE_REFUSED));
                }
            }
            if !csr_matches_certificate_identity(csr, peer)? {
                return Ok(plain_response(
                    StatusCode::BAD_REQUEST,
                    "a certificate issued by this CA can only be re-enrolled with the \
                     same Subject and SubjectAltName",
                ));
            }
        } else if is_enrollment_issued(peer)? {
            warn!("EST simpleenroll rejected: the client certificate was enrolled elsewhere");
            return Ok(plain_response(StatusCode::FORBIDDEN, CERTIFICATE_REFUSED));
        }
    }
    issue_and_respond(kms, csr).await
}

/// Re-enrollment core (RFC 7030 §4.2.2): `peer` is the TLS client certificate being renewed,
/// which must have been issued by the EST CA and still be active; `tls_unique` is the channel
/// binding of the connection (see [`check_tls_unique`]).
pub(crate) async fn simple_reenroll(
    kms: &KMS,
    peer: Option<&X509>,
    tls_unique: Option<&[u8]>,
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
        return Ok(plain_response(StatusCode::FORBIDDEN, CERTIFICATE_REFUSED));
    }

    let csr = decode_csr(body)?;
    if let Err(reason) = check_tls_unique(&csr, tls_unique) {
        warn!("EST simplereenroll rejected: {reason}");
        return Ok(plain_response(StatusCode::BAD_REQUEST, reason));
    }
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
    payload: Payload,
) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    let started = Instant::now();
    let client = client_ip(&kms, &req);
    info!("POST /.well-known/est/simplereenroll from {client}");
    let peer = req.conn_data::<PeerCertificate>().map(|p| p.cert.clone());
    let principal = peer.as_ref().map_or_else(
        || "unauthenticated".to_owned(),
        |p| format!("est-mtls:{}", subject_cn(p)),
    );
    let Some(_permit) = kms.enrollment_guard.try_begin() else {
        return Ok(busy_response());
    };
    let body = match read_limited_body(payload).await {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    let tls_unique = connection_tls_unique(&req);
    let result = simple_reenroll(&kms, peer.as_ref(), tls_unique.as_deref(), &body).await;
    audit_enrollment_result(
        &kms,
        OP_SIMPLEREENROLL,
        &principal,
        client,
        started,
        &result,
    );
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // tests: a panic is the failure signal
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::csr_attrs::csr_with_challenge_password;
    use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::X509NameBuilder};

    use super::*;

    fn csr(challenge: Option<&str>) -> X509Req {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "dev1.iot.example").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let req = b.build();
        match challenge {
            Some(c) => csr_with_challenge_password(&req, &key, c).unwrap(),
            None => req,
        }
    }

    #[test]
    fn tls_unique_challenge_must_match_the_connection() {
        let binding = [0xA5_u8; 12];
        let encoded = STANDARD.encode(binding);
        // no challengePassword: nothing to verify, with or without a binding
        assert_eq!(check_tls_unique(&csr(None), None), Ok(()));
        assert_eq!(check_tls_unique(&csr(None), Some(&binding)), Ok(()));
        // the right tls-unique value is accepted
        assert_eq!(
            check_tls_unique(&csr(Some(&encoded)), Some(&binding)),
            Ok(())
        );
        // a value from another connection is refused
        let other = STANDARD.encode([0x5A_u8; 12]);
        assert_ne!(check_tls_unique(&csr(Some(&other)), Some(&binding)), Ok(()));
        // a binding that cannot be checked (TLS 1.3, plain HTTP) is refused, not ignored
        assert_ne!(check_tls_unique(&csr(Some(&encoded)), None), Ok(()));
    }
}

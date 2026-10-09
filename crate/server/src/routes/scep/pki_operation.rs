//! `PKIOperation` (RFC 8894 §4.3): `PKCSReq` (initial enrollment with a challenge password)
//! and `RenewalReq` (renewal signed by a still-valid certificate of the same CA).
//!
//! `GetCert`, `GetCRL` and `CertPoll` are not implemented: `Certify` is synchronous, so
//! `PENDING` is never returned and no polling workflow exists.

use actix_web::HttpResponse;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::{
    csr_attrs::csr_challenge_password,
    scep_cms::{
        FAIL_INFO_BAD_CERT_ID, FAIL_INFO_BAD_MESSAGE_CHECK, FAIL_INFO_BAD_REQUEST,
        MESSAGE_TYPE_CERT_REP, MESSAGE_TYPE_PKCS_REQ, MESSAGE_TYPE_RENEWAL_REQ, NONCE_LEN,
        PKI_STATUS_FAILURE, PKI_STATUS_SUCCESS, ParsedPkiMessage, ScepAttrs,
        build_signed_pkimessage, certs_only_der, decrypt_envelope, envelope_for_recipient,
        parse_signed_pkimessage,
    },
};
use cosmian_logger::{info, warn};
use openssl::{
    pkey::{PKey, Private},
    x509::{X509, X509Req},
};

use crate::{
    core::KMS,
    error::KmsError,
    result::KResult,
    routes::enrollment::{
        csr_matches_certificate_identity, ensure_active_certificate_of_ca, issue_from_csr,
        load_ca_signing_material, secrets_equal,
    },
};

const CT_PKI_MESSAGE: &str = "application/x-pki-message";

/// Decode the `message` query parameter of a GET `PKIOperation` (base64; `+` may have been
/// turned into a space by lenient query-string decoding).
pub(super) fn decode_get_message(message: &str) -> Result<Vec<u8>, String> {
    let compact: String = message
        .chars()
        .filter(|c| !c.is_ascii_whitespace() || *c == ' ')
        .map(|c| if c == ' ' { '+' } else { c })
        .collect();
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| format!("invalid base64 `message` parameter: {e}"))
}

/// A failed enrollment: the `failInfo` to report and a log message.
struct Rejection {
    fail_info: u8,
    reason: String,
}

impl Rejection {
    fn new(fail_info: u8, reason: impl Into<String>) -> Self {
        Self {
            fail_info,
            reason: reason.into(),
        }
    }
}

fn pki_message_response(der: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok().content_type(CT_PKI_MESSAGE).body(der)
}

fn fresh_nonce() -> KResult<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    openssl::rand::rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Process a signed `pkiMessage` and produce the `CertRep` response.
pub(super) async fn pki_operation(kms: &KMS, message_der: &[u8]) -> KResult<HttpResponse> {
    // A message we cannot even parse has no transactionID/nonce to answer with.
    let parsed = match parse_signed_pkimessage(message_der) {
        Ok(p) => p,
        Err(e) => {
            warn!("SCEP: unreadable pkiMessage: {e}");
            return Ok(super::bad_request(
                "malformed or unverifiable SCEP pkiMessage",
            ));
        }
    };
    let ca_uid = kms
        .params
        .scep_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("SCEP enabled without scep_ca_uid".to_owned()))?;
    let (ca_cert, ca_key) = load_ca_signing_material(kms, ca_uid).await?;

    let attrs = &parsed.attrs;
    info!(
        "SCEP PKIOperation: messageType={} transactionID={}",
        attrs.message_type, attrs.transaction_id
    );

    let outcome = enroll(kms, ca_uid, &ca_cert, &ca_key, &parsed).await;
    let cert_rep = match outcome {
        Ok(issued) => {
            let envelope =
                envelope_for_recipient(&parsed.signer_cert, &certs_only_der(&[issued])?)?;
            build_signed_pkimessage(
                &ca_cert,
                &ca_key,
                &envelope,
                &cert_rep_attrs(&parsed, PKI_STATUS_SUCCESS, None)?,
            )?
        }
        Err(rejection) => {
            warn!(
                "SCEP request {} rejected (failInfo={}): {}",
                attrs.transaction_id, rejection.fail_info, rejection.reason
            );
            build_signed_pkimessage(
                &ca_cert,
                &ca_key,
                &[],
                &cert_rep_attrs(&parsed, PKI_STATUS_FAILURE, Some(rejection.fail_info))?,
            )?
        }
    };
    Ok(pki_message_response(cert_rep))
}

fn cert_rep_attrs(
    request: &ParsedPkiMessage,
    status: u8,
    fail_info: Option<u8>,
) -> KResult<ScepAttrs> {
    Ok(ScepAttrs {
        transaction_id: request.attrs.transaction_id.clone(),
        message_type: MESSAGE_TYPE_CERT_REP,
        pki_status: Some(status),
        fail_info,
        sender_nonce: fresh_nonce()?,
        recipient_nonce: Some(request.attrs.sender_nonce),
    })
}

/// Authenticate, authorise and execute one `PKCSReq` / `RenewalReq`.
async fn enroll(
    kms: &KMS,
    ca_uid: &str,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    request: &ParsedPkiMessage,
) -> Result<X509, Rejection> {
    let message_type = request.attrs.message_type;
    if message_type != MESSAGE_TYPE_PKCS_REQ && message_type != MESSAGE_TYPE_RENEWAL_REQ {
        return Err(Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            format!("unsupported SCEP messageType {message_type}"),
        ));
    }
    if message_type == MESSAGE_TYPE_RENEWAL_REQ && !kms.params.scep_allow_renewal_without_challenge
    {
        return Err(Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            "RenewalReq is disabled (scep_allow_renewal_without_challenge = false)",
        ));
    }

    let csr_der = decrypt_envelope(&request.content, ca_key, ca_cert).map_err(|e| {
        Rejection::new(
            FAIL_INFO_BAD_MESSAGE_CHECK,
            format!("cannot decrypt the pkcsPKIEnvelope: {e}"),
        )
    })?;
    let csr = X509Req::from_der(&csr_der).map_err(|e| {
        Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            format!("invalid PKCS#10 request: {e}"),
        )
    })?;

    if message_type == MESSAGE_TYPE_PKCS_REQ {
        let expected = kms.params.scep_challenge_password.as_deref();
        let supplied = csr_challenge_password(&csr);
        let authorised = matches!((expected, supplied.as_deref()),
            (Some(expected), Some(supplied)) if secrets_equal(expected, supplied));
        if !authorised {
            return Err(Rejection::new(
                FAIL_INFO_BAD_REQUEST,
                "missing or wrong challengePassword",
            ));
        }
    } else {
        // RenewalReq (RFC 8894 §2.3): authenticated by the signature of a still-valid
        // certificate of this CA; no challengePassword is needed.
        ensure_active_certificate_of_ca(kms, ca_uid, ca_cert, &request.signer_cert)
            .await
            .map_err(|e| Rejection::new(FAIL_INFO_BAD_CERT_ID, e.to_string()))?;
        // A certificate can only be renewed for the identity it already carries.
        let same_identity = csr_matches_certificate_identity(&csr, &request.signer_cert)
            .map_err(|e| Rejection::new(FAIL_INFO_BAD_REQUEST, e.to_string()))?;
        if !same_identity {
            return Err(Rejection::new(
                FAIL_INFO_BAD_REQUEST,
                "the renewal request Subject/SubjectAltName differs from the certificate being renewed",
            ));
        }
    }

    issue_from_csr(kms, ca_uid, &csr, kms.params.scep_template.as_ref(), None)
        .await
        .map_err(|e| match e {
            KmsError::InvalidRequest(_) => Rejection::new(FAIL_INFO_BAD_REQUEST, e.to_string()),
            other => Rejection::new(FAIL_INFO_BAD_REQUEST, format!("issuance failed: {other}")),
        })
}

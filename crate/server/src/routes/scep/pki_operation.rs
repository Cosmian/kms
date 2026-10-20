//! `PKIOperation` (RFC 8894 §4.3): `PKCSReq` (initial enrollment with a challenge password)
//! and `RenewalReq` (renewal signed by a still-valid certificate of the same CA).
//!
//! `GetCert`, `GetCRL` and `CertPoll` are not implemented: `Certify` is synchronous, so
//! `PENDING` is never returned and no polling workflow exists.
//!
//! Failure reporting is deliberately uniform: every failure of an authenticated-looking
//! message (undecryptable envelope, unreadable request, wrong challenge, policy violation)
//! returns `badRequest`, so that the `failInfo` of a signed `CertRep` cannot be used as a
//! decryption or padding oracle. The detailed reason is logged only.

use std::{net::IpAddr, time::Instant};

use actix_web::HttpResponse;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::KmsRng,
    openssl::{
        csr_attrs::csr_challenge_password,
        scep_cms::{
            FAIL_INFO_BAD_CERT_ID, FAIL_INFO_BAD_REQUEST, MESSAGE_TYPE_CERT_REP,
            MESSAGE_TYPE_PKCS_REQ, MESSAGE_TYPE_RENEWAL_REQ, NONCE_LEN, PKI_STATUS_FAILURE,
            PKI_STATUS_SUCCESS, ParsedPkiMessage, ScepAttrs, build_signed_pkimessage,
            certs_only_der, decrypt_envelope, envelope_for_recipient, parse_signed_pkimessage,
        },
    },
};
use cosmian_logger::{info, warn};
use openssl::{
    pkey::{PKey, Private},
    sha::sha256,
    x509::{X509, X509Req},
};

use crate::{
    core::KMS,
    error::KmsError,
    result::KResult,
    routes::enrollment::{
        IssuedCertificate, MAX_ENROLLMENT_BODY, audit_enrollment, busy_response,
        csr_matches_certificate_identity, ensure_active_certificate_of_ca, issue_from_csr,
        load_ca_signing_material, locked_response, log_safe, secrets_equal, subject_cn,
    },
};

const CT_PKI_MESSAGE: &str = "application/x-pki-message";

/// Operation name recorded in the audit trail.
const OP_PKI_OPERATION: &str = "ScepPkiOperation";

/// Longest `transactionID` accepted. RFC 8894 §3.2.1.1 derives it from a hash of the public
/// key, i.e. at most 64 hexadecimal digits.
const MAX_TRANSACTION_ID_LEN: usize = 128;

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

/// The `transactionID` is echoed and logged: refuse anything that is not short printable ASCII.
fn valid_transaction_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_TRANSACTION_ID_LEN && id.bytes().all(|b| b.is_ascii_graphic())
}

/// A failed enrollment: the `failInfo` to report and a log message.
struct Rejection {
    fail_info: u8,
    reason: String,
    /// `true` when the failure counts towards the lockout of the client (it failed to
    /// authenticate, or replayed a message).
    counts_as_failure: bool,
}

impl Rejection {
    fn new(fail_info: u8, reason: impl Into<String>) -> Self {
        Self {
            fail_info,
            reason: reason.into(),
            counts_as_failure: false,
        }
    }

    const fn counted(mut self) -> Self {
        self.counts_as_failure = true;
        self
    }
}

fn pki_message_response(der: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok().content_type(CT_PKI_MESSAGE).body(der)
}

fn fresh_nonce(rng: &KmsRng) -> KResult<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    // Sent to the client in clear: public DRBG.
    rng.fill_public_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Process a signed `pkiMessage` and produce the `CertRep` response.
pub(super) async fn pki_operation(
    kms: &KMS,
    client: IpAddr,
    message_der: &[u8],
) -> KResult<HttpResponse> {
    let started = Instant::now();
    if let Some(wait) = kms.enrollment_guard.locked_for(client) {
        warn!("SCEP PKIOperation refused: {client} is locked out");
        return Ok(locked_response(wait));
    }
    if message_der.len() > MAX_ENROLLMENT_BODY {
        return Ok(HttpResponse::PayloadTooLarge().finish());
    }
    let Some(_permit) = kms.enrollment_guard.try_begin() else {
        return Ok(busy_response());
    };

    // A message we cannot even parse has no transactionID/nonce to answer with.
    let parsed = match parse_signed_pkimessage(message_der) {
        Ok(p) => p,
        Err(e) => {
            warn!("SCEP: unreadable pkiMessage from {client}: {e}");
            return Ok(super::bad_request(
                "malformed or unverifiable SCEP pkiMessage",
            ));
        }
    };
    if !valid_transaction_id(&parsed.attrs.transaction_id) {
        warn!(
            "SCEP: refusing a pkiMessage from {client} with an invalid transactionID ({})",
            log_safe(&parsed.attrs.transaction_id)
        );
        return Ok(super::bad_request("invalid SCEP transactionID"));
    }
    let ca_uid = kms
        .params
        .scep_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("SCEP enabled without scep_ca_uid".to_owned()))?;
    let (ca_cert, ca_key) = load_ca_signing_material(kms, ca_uid).await?;

    let attrs = &parsed.attrs;
    info!(
        "SCEP PKIOperation from {client}: messageType={} transactionID={}",
        attrs.message_type, attrs.transaction_id
    );

    let mut principal = "unauthenticated".to_owned();
    let outcome = enroll(kms, ca_uid, &ca_cert, &ca_key, &parsed, &mut principal).await;
    let cert_rep = match outcome {
        Ok(issued) => {
            kms.enrollment_guard.record_success(client);
            audit_enrollment(
                kms,
                OP_PKI_OPERATION,
                &principal,
                client,
                started,
                &Ok(issued.uid),
            );
            let envelope = envelope_for_recipient(
                &parsed.signer_cert,
                &certs_only_der(&[issued.certificate])?,
            )?;
            build_signed_pkimessage(
                &ca_cert,
                &ca_key,
                &envelope,
                &cert_rep_attrs(kms, &parsed, PKI_STATUS_SUCCESS, None)?,
            )?
        }
        Err(rejection) => {
            if rejection.counts_as_failure {
                kms.enrollment_guard.record_failure(client);
            }
            warn!(
                "SCEP request {} rejected (failInfo={}): {}",
                attrs.transaction_id, rejection.fail_info, rejection.reason
            );
            audit_enrollment(
                kms,
                OP_PKI_OPERATION,
                &principal,
                client,
                started,
                &Err(rejection.reason),
            );
            build_signed_pkimessage(
                &ca_cert,
                &ca_key,
                &[],
                &cert_rep_attrs(kms, &parsed, PKI_STATUS_FAILURE, Some(rejection.fail_info))?,
            )?
        }
    };
    Ok(pki_message_response(cert_rep))
}

fn cert_rep_attrs(
    kms: &KMS,
    request: &ParsedPkiMessage,
    status: u8,
    fail_info: Option<u8>,
) -> KResult<ScepAttrs> {
    Ok(ScepAttrs {
        transaction_id: request.attrs.transaction_id.clone(),
        message_type: MESSAGE_TYPE_CERT_REP,
        pki_status: Some(status),
        fail_info,
        sender_nonce: fresh_nonce(&kms.rng)?,
        recipient_nonce: Some(request.attrs.sender_nonce),
    })
}

/// Identity of an authenticated message, for the replay cache: the signer certificate, the
/// transactionID and the sender nonce.
fn message_fingerprint(request: &ParsedPkiMessage) -> Result<[u8; 32], Rejection> {
    let mut bytes = request
        .signer_cert
        .to_der()
        .map_err(|e| Rejection::new(FAIL_INFO_BAD_REQUEST, format!("signer certificate: {e}")))?;
    bytes.extend_from_slice(request.attrs.transaction_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&request.attrs.sender_nonce);
    Ok(sha256(&bytes))
}

/// Authenticate, authorise and execute one `PKCSReq` / `RenewalReq`. `principal` is set once
/// the message is authenticated.
async fn enroll(
    kms: &KMS,
    ca_uid: &str,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    request: &ParsedPkiMessage,
    principal: &mut String,
) -> Result<IssuedCertificate, Rejection> {
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
    if message_type == MESSAGE_TYPE_RENEWAL_REQ {
        // RFC 8894 §2.3: a renewal is authenticated by the signature of a still-valid
        // certificate of this CA. Checked before the envelope is decrypted so that a signer
        // that is not valid never costs a private-key operation, and so that the reported
        // failure does not depend on whether the envelope decrypts.
        ensure_active_certificate_of_ca(kms, ca_uid, ca_cert, &request.signer_cert)
            .await
            .map_err(|e| Rejection::new(FAIL_INFO_BAD_CERT_ID, e.to_string()).counted())?;
    }

    let csr_der = decrypt_envelope(&request.content, ca_key, ca_cert).map_err(|e| {
        Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            format!("cannot decrypt the pkcsPKIEnvelope: {e}"),
        )
        .counted()
    })?;
    let csr = X509Req::from_der(&csr_der).map_err(|e| {
        Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            format!("invalid PKCS#10 request: {e}"),
        )
        .counted()
    })?;

    if message_type == MESSAGE_TYPE_PKCS_REQ {
        let expected = kms.params.scep_challenge_password.as_deref();
        let supplied = csr_challenge_password(&csr);
        let authorised = matches!((expected, supplied.as_deref()),
            (Some(expected), Some(supplied)) if secrets_equal(expected, supplied));
        if !authorised {
            return Err(
                Rejection::new(FAIL_INFO_BAD_REQUEST, "missing or wrong challengePassword")
                    .counted(),
            );
        }
        "scep-challenge".clone_into(principal);
    } else {
        // A certificate can only be renewed for the identity it already carries.
        *principal = format!("scep-renewal:{}", subject_cn(&request.signer_cert));
        let same_identity = csr_matches_certificate_identity(&csr, &request.signer_cert)
            .map_err(|e| Rejection::new(FAIL_INFO_BAD_REQUEST, e.to_string()))?;
        if !same_identity {
            return Err(Rejection::new(
                FAIL_INFO_BAD_REQUEST,
                "the renewal request Subject/SubjectAltName differs from the certificate being renewed",
            ));
        }
    }

    // Authenticated: remember the message so that a captured copy cannot be replayed to make
    // the CA issue again.
    if !kms
        .enrollment_guard
        .register_message(message_fingerprint(request)?)
    {
        return Err(Rejection::new(
            FAIL_INFO_BAD_REQUEST,
            "replayed SCEP message (or replay cache full)",
        )
        .counted());
    }

    issue_from_csr(kms, ca_uid, &csr, kms.params.scep_template.as_ref(), None)
        .await
        .map_err(|e| match e {
            KmsError::InvalidRequest(_) => Rejection::new(FAIL_INFO_BAD_REQUEST, e.to_string()),
            other => Rejection::new(FAIL_INFO_BAD_REQUEST, format!("issuance failed: {other}")),
        })
}

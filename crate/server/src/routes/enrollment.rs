//! Helpers shared by the EST (RFC 7030) and SCEP (RFC 8894) enrollment endpoints.
//!
//! Both protocols issue certificates from a configured CA certificate (`est_ca_uid` /
//! `scep_ca_uid`) through the regular KMIP `Certify` operation, constrained by a
//! [`CertTemplate`]. Issuance runs as the reserved [`ENROLLMENT_SERVICE_USER`], which may only
//! use a CA whose owner granted it the `certify` right on the CA certificate and private key;
//! the issued certificate is stored under the CA owner.

use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Duration, Instant},
};

use actix_web::{
    HttpRequest, HttpResponse,
    http::header,
    web::{Bytes, Payload},
};
use cosmian_kms_access::audit::{
    AuditEventDraft, AuditResult, OperationAuditContext, RequestAuditContext, audit_now,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::Certify,
            kmip_types::{CertificateRequestType, LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, oid::nid_of,
    },
    cosmian_kms_interfaces::ObjectHandle,
};
use cosmian_logger::{debug, error, info, warn};
use openssl::{
    asn1::Asn1Time,
    nid::Nid,
    pkey::{PKey, Private},
    sha::sha256,
    x509::{X509, X509Req},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x509_parser::{
    asn1_rs::{Any, Tag},
    cri_attributes::ParsedCriAttribute,
    prelude::{FromDer, X509Certificate, X509CertificationRequest},
};

use super::enrollment_guard::UNKNOWN_CLIENT;
use crate::{
    core::{
        KMS,
        certificate::retrieve_issuer_private_key_and_certificate,
        operations::certify::{certify_for_owner, template::CertTemplate},
    },
    error::KmsError,
    middlewares::{UserId, forwarded_for, is_enrollment_issued, resolve_client_ip},
    result::{KResult, KResultHelper},
};

/// Maximum number of certificates followed when walking up an issuer chain.
const MAX_CHAIN_DEPTH: usize = 8;

/// Reserved identity under which EST/SCEP use the CA key.
///
/// Like `AWS_XKS_SERVICE_USER`, it is wrapped in square brackets and rejected on every
/// externally-derived authentication path (`reject_reserved_service_identity`), so no client
/// can authenticate as it. It holds no right by default: a CA owner delegates a CA to
/// enrollment by granting it `certify` on the CA certificate and its private key (plus
/// `decrypt` on the wrapping key when the CA key is wrapped, and the `create` right when Crypto
/// Officers are configured).
pub(crate) const ENROLLMENT_SERVICE_USER: &str = "[enrollment-service]";

/// Server-side hint logged when the CA cannot be used by the enrollment service identity.
fn log_ca_use_failure(ca_uid: &str, error: &KmsError) {
    warn!(
        "enrollment: CA `{ca_uid}` could not be used by `{ENROLLMENT_SERVICE_USER}`: {error}. \
         The CA owner must grant it `certify` on the CA certificate and private key (and \
         `decrypt` on the wrapping key if the CA key is wrapped)."
    );
}

/// Compare two secrets in constant time (both are hashed first so that the length is not leaked).
pub(crate) fn secrets_equal(a: &str, b: &str) -> bool {
    sha256(a.as_bytes()).ct_eq(&sha256(b.as_bytes())).into()
}

/// Address of the client of `req`, honouring `X-Forwarded-For` only from the configured
/// trusted proxies (the same rule as the audit middleware).
pub(crate) fn client_ip(kms: &KMS, req: &HttpRequest) -> IpAddr {
    resolve_client_ip(
        req.peer_addr().map(|a| a.ip()),
        forwarded_for(req.headers()).as_deref(),
        &kms.params.audit_trusted_proxy_cidrs,
    )
    .unwrap_or(UNKNOWN_CLIENT)
}

/// Make an attacker-controlled string safe to log: control characters (log forging) are
/// replaced and the length is bounded.
pub(crate) fn log_safe(value: &str) -> String {
    const MAX_LEN: usize = 128;
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_LEN)
        .collect()
}

/// Record one enrollment attempt in the tamper-evident audit store (when enabled) and in the
/// log: `info` for a success, `warn` for a failure. `principal` is how the caller
/// authenticated (`est-basic:<user>`, `est-mtls:<CN>`, `scep-challenge`, ...), or
/// `unauthenticated`.
pub(crate) fn audit_enrollment(
    kms: &KMS,
    operation: &str,
    principal: &str,
    client: IpAddr,
    started: Instant,
    outcome: &Result<String, String>,
) {
    let (object_uid, result) = match outcome {
        Ok(uid) => (Some(uid.clone()), AuditResult::Success),
        Err(reason) => (None, AuditResult::Failure(log_safe(reason))),
    };
    let principal = log_safe(principal);
    match outcome {
        Ok(uid) => info!(
            "enrollment audit: {operation} succeeded for `{principal}` from {client}: \
             certificate {uid}"
        ),
        Err(reason) => warn!(
            "enrollment audit: {operation} refused for `{principal}` from {client}: {}",
            log_safe(reason)
        ),
    }
    let Some(store) = &kms.audit_store else {
        return;
    };
    let draft = AuditEventDraft::build(
        &RequestAuditContext {
            timestamp: audit_now(),
            user: principal,
            client_ip: Some(client.to_string()),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            request_id: Some(Uuid::new_v4()),
        },
        OperationAuditContext {
            operation: operation.to_owned(),
            object_uid,
            algorithm: None,
        },
        result,
    );
    if !store.enqueue(std::iter::once(draft)) {
        // The certificate may already be issued, so a refusal would not undo anything.
        error!("enrollment audit: {operation} event could not be queued");
    }
}

/// What an enrollment handler tells its caller about the outcome, carried in the response
/// extensions so that the audit trail can record the issued certificate without changing the
/// handler signatures: `Ok(uid)` of the issued certificate, `Err(reason)` of a refusal.
#[derive(Clone)]
pub(crate) struct EnrollmentOutcome(pub(crate) Result<String, String>);

/// Audit the result of an enrollment handler (see [`audit_enrollment`]).
pub(crate) fn audit_enrollment_result(
    kms: &KMS,
    operation: &str,
    principal: &str,
    client: IpAddr,
    started: Instant,
    result: &KResult<HttpResponse>,
) {
    let outcome = match result {
        Err(e) => Err(e.to_string()),
        Ok(response) => response
            .extensions()
            .get::<EnrollmentOutcome>()
            .map_or_else(
                || {
                    if response.status().is_success() {
                        Ok("-".to_owned())
                    } else {
                        Err(format!("HTTP {}", response.status().as_u16()))
                    }
                },
                |outcome| outcome.0.clone(),
            ),
    };
    audit_enrollment(kms, operation, principal, client, started, &outcome);
}

/// Largest EST / SCEP request body: a PKCS#10 request or a CMS message is a few KiB, while the
/// server-wide payload limit is sized for KMIP objects.
pub(crate) const MAX_ENROLLMENT_BODY: usize = 64 * 1024;

/// Read a request body of at most [`MAX_ENROLLMENT_BODY`] bytes; the error is the response to
/// send back.
pub(crate) async fn read_limited_body(payload: Payload) -> Result<Bytes, HttpResponse> {
    match payload.to_bytes_limited(MAX_ENROLLMENT_BODY).await {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(_)) => Err(HttpResponse::BadRequest().finish()),
        Err(_) => Err(HttpResponse::PayloadTooLarge().finish()),
    }
}

/// `429` for a client that is locked out after repeated failed authentications.
pub(crate) fn locked_response(wait: Duration) -> HttpResponse {
    HttpResponse::TooManyRequests()
        .insert_header((header::RETRY_AFTER, wait.as_secs().max(1).to_string()))
        .finish()
}

/// `503` when the concurrent enrollment limit is reached.
pub(crate) fn busy_response() -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header((header::RETRY_AFTER, "5"))
        .finish()
}

/// Common Name of `cert`'s subject, `?` when it has none.
pub(crate) fn subject_cn(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
        .unwrap_or_else(|| "?".to_owned())
}

/// Load the CA certificate `ca_uid` followed by its issuers, up to the root.
pub(crate) async fn load_ca_chain(kms: &KMS, ca_uid: &str) -> KResult<Vec<X509>> {
    let mut chain = Vec::new();
    let mut uid = ca_uid.to_owned();
    while chain.len() < MAX_CHAIN_DEPTH {
        let owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .context("retrieve CA certificate")?
            .ok_or_else(|| {
                // The UID is operator configuration: log it, do not echo it to clients.
                warn!("enrollment: CA certificate not found: {uid}");
                KmsError::ItemNotFound("the enrollment CA certificate is not available".to_owned())
            })?;
        chain.push(kmip_certificate_to_openssl(owm.object())?);
        let Some(parent) = owm.attributes().get_link(LinkType::CertificateLink) else {
            break;
        };
        let parent = parent.to_string();
        if parent == uid {
            break;
        }
        uid = parent;
    }
    Ok(chain)
}

/// Load the CA certificate and its (unwrapped) private key.
pub(crate) async fn load_ca_signing_material(
    kms: &KMS,
    ca_uid: &str,
) -> KResult<(X509, PKey<Private>)> {
    let user = UserId::from(ENROLLMENT_SERVICE_USER);
    let ca_uid = ca_uid.to_owned();
    let (private_key, certificate) = Box::pin(retrieve_issuer_private_key_and_certificate(
        None,
        Some(ObjectHandle::from(&ca_uid)),
        kms,
        &user,
    ))
    .await
    .inspect_err(|e| log_ca_use_failure(&ca_uid, e))?;
    if private_key.state() != State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "the CA private key '{}' is not Active",
            private_key.id()
        )));
    }
    let unwrapped = Box::pin(kms.get_unwrapped(private_key.id(), private_key.object(), &user))
        .await
        .inspect_err(|e| log_ca_use_failure(&ca_uid, e))?;
    Ok((
        kmip_certificate_to_openssl(certificate.object())?,
        kmip_private_key_to_openssl(&unwrapped)?,
    ))
}

/// A certificate issued by [`issue_from_csr`].
pub(crate) struct IssuedCertificate {
    /// KMS unique identifier of the stored certificate.
    pub(crate) uid: String,
    pub(crate) certificate: X509,
}

/// System tag under which an enrolled certificate is indexed by issuer and serial, so that the
/// state of a certificate presented for renewal is found without scanning every certificate
/// of the CA.
pub(crate) fn serial_tag(ca_uid: &str, serial_hex: &str) -> String {
    format!(
        "_enrolled_serial:{ca_uid}:{}",
        serial_hex.to_ascii_uppercase()
    )
}

/// Refuse a built certificate that is not a plain end-entity enrollment certificate:
/// `basicConstraints` `CA:TRUE`, `keyCertSign` or a missing marker policy means the CSR policy
/// was bypassed somewhere between validation and issuance.
fn assert_enrolled_leaf(certificate: &X509) -> KResult<()> {
    let der = certificate.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|e| {
        KmsError::ServerError(format!("cannot inspect the issued certificate: {e}"))
    })?;
    let is_ca = parsed
        .basic_constraints()
        .map_err(|e| KmsError::ServerError(format!("issued certificate basicConstraints: {e}")))?
        .is_some_and(|bc| bc.value.ca);
    let key_cert_sign = parsed
        .key_usage()
        .map_err(|e| KmsError::ServerError(format!("issued certificate keyUsage: {e}")))?
        .is_some_and(|ku| ku.value.key_cert_sign());
    if is_ca || key_cert_sign || !is_enrollment_issued(certificate)? {
        return Err(KmsError::ServerError(
            "the issued certificate does not conform to the enrollment policy (CA capability or \
             missing enrolled-certificate marker)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Issue a certificate for `csr` from the CA `ca_uid` after enforcing `template`
/// (a baseline template when `None`). The certificate is stored under the CA certificate owner.
pub(crate) async fn issue_from_csr(
    kms: &KMS,
    ca_uid: &str,
    csr: &X509Req,
    template: Option<&CertTemplate>,
    requested_validity_days: Option<u32>,
) -> KResult<IssuedCertificate> {
    let user = UserId::from(ENROLLMENT_SERVICE_USER);
    let ca_owner = kms
        .database
        .retrieve_object(ca_uid)
        .await
        .context("retrieve CA certificate")?
        .ok_or_else(|| KmsError::ItemNotFound(format!("CA certificate not found: {ca_uid}")))?
        .owner_id()
        .to_owned();
    let mut attributes = Attributes::default();
    attributes.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(ca_uid.to_owned()),
    );
    let baseline = CertTemplate::default();
    template.unwrap_or(&baseline).apply(
        csr,
        kms.vendor_id(),
        requested_validity_days,
        &mut attributes,
    )?;
    let response = Box::pin(certify_for_owner(
        kms,
        Certify {
            unique_identifier: None,
            certificate_request_type: Some(CertificateRequestType::PKCS10),
            certificate_request_value: Some(csr.to_der()?),
            attributes: Some(attributes),
            protection_storage_masks: None,
        },
        &user,
        &ca_owner,
    ))
    .await
    .inspect_err(|e| log_ca_use_failure(ca_uid, e))?;
    let uid = response.unique_identifier.to_string();
    let owm = kms
        .database
        .retrieve_object(&uid)
        .await
        .context("retrieve issued certificate")?
        .ok_or_else(|| KmsError::ItemNotFound(format!("issued certificate not found: {uid}")))?;
    let certificate = kmip_certificate_to_openssl(owm.object())?;

    // Last line of defence, after the builder and before the certificate is handed out: a
    // certificate that is not a plain leaf is taken out of service.
    if let Err(e) = assert_enrolled_leaf(&certificate) {
        error!("enrollment: deactivating non-conforming certificate {uid}: {e}");
        kms.database
            .update_state(&uid, State::Deactivated)
            .await
            .context("deactivate non-conforming certificate")?;
        return Err(e);
    }

    let serial_hex = certificate
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string();
    let mut tags = kms
        .database
        .retrieve_tags(&uid)
        .await
        .context("retrieve issued certificate tags")?;
    tags.insert(serial_tag(ca_uid, &serial_hex));
    kms.database
        .update_object(&uid, owm.object(), owm.attributes(), Some(&tags))
        .await
        .context("index issued certificate by serial")?;
    debug!("enrollment: issued certificate {uid} (serial {serial_hex}) from CA {ca_uid}");
    Ok(IssuedCertificate { uid, certificate })
}

/// `true` when `cert` names `ca_cert` as issuer and carries a valid signature from its key.
pub(crate) fn is_issued_by(cert: &X509, ca_cert: &X509) -> KResult<bool> {
    let ca_public_key = ca_cert.public_key()?;
    Ok(
        cert.issuer_name().to_der()? == ca_cert.subject_name().to_der()?
            && cert.verify(&ca_public_key)?,
    )
}

/// Check that `cert` was issued by the CA `ca_cert` (`ca_uid`), is within its validity period
/// and is tracked by the KMS in the `Active` state (i.e. not revoked / deactivated / destroyed).
///
/// The errors describe the reason for the log; callers must not forward them to the client.
pub(crate) async fn ensure_active_certificate_of_ca(
    kms: &KMS,
    ca_uid: &str,
    ca_cert: &X509,
    cert: &X509,
) -> KResult<()> {
    if !is_issued_by(cert, ca_cert)? {
        return Err(KmsError::InvalidRequest(
            "the certificate was not issued by the enrollment CA".to_owned(),
        ));
    }
    let now = Asn1Time::days_from_now(0)?;
    if cert.not_after() < now || cert.not_before() > now {
        return Err(KmsError::InvalidRequest(
            "the certificate is not within its validity period".to_owned(),
        ));
    }
    let serial_hex = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    let tag = HashSet::from([serial_tag(ca_uid, &serial_hex)]);
    let presented_der = cert.to_der()?;
    let mut found = None;
    for uid in kms
        .database
        .list_uids_for_tags(&tag)
        .await
        .context("list_uids_for_tags")?
    {
        let Some(owm) = kms
            .database
            .retrieve_object_arc(&uid)
            .await
            .context("retrieve enrolled certificate")?
        else {
            continue;
        };
        // The tag only locates candidates: the stored certificate must be the presented one.
        if kmip_certificate_to_openssl(owm.object())?.to_der()? == presented_der {
            found = Some((uid, owm.state()));
            break;
        }
    }
    if found.is_none() {
        // Certificates issued before the serial index existed (or in the short window between
        // issuance and indexing): fall back to the scan.
        found = Box::pin(kms.database.find_certificate_by_serial(
            ca_uid,
            &serial_hex,
            kms.vendor_id(),
        ))
        .await
        .context("find_certificate_by_serial")?
        .map(|(uid, state, _)| (uid, state));
    }
    match found {
        Some((_, State::Active)) => Ok(()),
        Some((uid, state)) => Err(KmsError::InvalidRequest(format!(
            "the certificate {uid} is in state {state} and cannot be renewed"
        ))),
        None => Err(KmsError::InvalidRequest(
            "the certificate is not known to the KMS".to_owned(),
        )),
    }
}

/// Sorted raw DER of every `GeneralName` in a `SubjectAltName` extension value. Comparing the
/// encoded names avoids any dependence on a parser's `Debug` rendering; a value that is not a
/// well-formed `SEQUENCE OF` TLVs is an error, never an empty set.
fn san_entries(value: &[u8]) -> KResult<Vec<Vec<u8>>> {
    let bad = |what: &str| KmsError::InvalidRequest(format!("invalid SubjectAltName: {what}"));
    let (rest, seq) = Any::from_der(value).map_err(|e| bad(&e.to_string()))?;
    if !rest.is_empty() || seq.tag() != Tag::Sequence {
        return Err(bad("not a single SEQUENCE"));
    }
    let mut data = seq.data;
    let mut out = Vec::new();
    while !data.is_empty() {
        let (next, _) = Any::from_der(data).map_err(|e| bad(&e.to_string()))?;
        let consumed = data
            .len()
            .checked_sub(next.len())
            .and_then(|n| data.get(..n))
            .ok_or_else(|| bad("inconsistent length"))?;
        out.push(consumed.to_vec());
        data = next;
    }
    out.sort();
    Ok(out)
}

/// `GeneralName`s of the `SubjectAltName` requested by a CSR.
fn csr_san_set(csr: &X509Req) -> KResult<Vec<Vec<u8>>> {
    let der = csr.to_der()?;
    let (_, parsed) = X509CertificationRequest::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid CSR: {e}")))?;
    for attr in parsed.certification_request_info.iter_attributes() {
        if let ParsedCriAttribute::ExtensionRequest(requested) = attr.parsed_attribute() {
            if let Some(ext) = requested
                .extensions
                .iter()
                .find(|e| nid_of(&e.oid.to_id_string()) == Nid::SUBJECT_ALT_NAME)
            {
                return san_entries(ext.value);
            }
        }
    }
    Ok(Vec::new())
}

/// `GeneralName`s of the `SubjectAltName` carried by a certificate.
fn cert_san_set(cert: &X509) -> KResult<Vec<Vec<u8>>> {
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid certificate: {e}")))?;
    parsed
        .extensions()
        .iter()
        .find(|e| nid_of(&e.oid.to_id_string()) == Nid::SUBJECT_ALT_NAME)
        .map_or_else(|| Ok(Vec::new()), |ext| san_entries(ext.value))
}

/// `true` when the Subject and the `SubjectAltName` of `csr` are identical to those of `cert`
/// (RFC 7030 §4.2.2; also required for SCEP renewals so that a certificate can only be
/// renewed for the identity it already carries).
pub(crate) fn csr_matches_certificate_identity(csr: &X509Req, cert: &X509) -> KResult<bool> {
    if csr.subject_name().to_der()? != cert.subject_name().to_der()? {
        return Ok(false);
    }
    let requested_sans = csr_san_set(csr)?;
    let certified_sans = cert_san_set(cert)?;
    Ok(requested_sans == certified_sans)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test-only assertions on known-good fixtures
mod tests {
    use super::san_entries;

    // SAN = SEQUENCE { dNSName "a", dNSName "b" } and the same names in the other order
    const AB: [u8; 8] = [0x30, 0x06, 0x82, 0x01, b'a', 0x82, 0x01, b'b'];
    const BA: [u8; 8] = [0x30, 0x06, 0x82, 0x01, b'b', 0x82, 0x01, b'a'];

    #[test]
    fn san_comparison_ignores_order_but_not_names() {
        assert_eq!(san_entries(&AB).unwrap(), san_entries(&BA).unwrap());
        let other: [u8; 8] = [0x30, 0x06, 0x82, 0x01, b'a', 0x82, 0x01, b'c'];
        assert_ne!(san_entries(&AB).unwrap(), san_entries(&other).unwrap());
    }

    #[test]
    fn malformed_san_is_an_error_not_an_empty_set() {
        // truncated element, trailing bytes, and not a SEQUENCE
        san_entries(&[0x30, 0x03, 0x82, 0x01]).unwrap_err();
        san_entries(&[0x30, 0x00, 0x00]).unwrap_err();
        san_entries(&[0x04, 0x00]).unwrap_err();
    }
}

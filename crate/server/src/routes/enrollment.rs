//! Helpers shared by the EST (RFC 7030) and SCEP (RFC 8894) enrollment endpoints.
//!
//! Both protocols issue certificates from a configured CA certificate (`est_ca_uid` /
//! `scep_ca_uid`) through the regular KMIP `Certify` operation, executed as the server
//! identity (`default_username`), and constrained by a [`CertTemplate`].

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::Certify,
            kmip_types::{CertificateRequestType, LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::{kmip_certificate_to_openssl, kmip_private_key_to_openssl},
    cosmian_kms_interfaces::ObjectHandle,
};
use cosmian_logger::debug;
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    sha::sha256,
    x509::{X509, X509Req},
};
use subtle::ConstantTimeEq;
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate, X509CertificationRequest};

use crate::{
    core::{
        KMS, certificate::retrieve_issuer_private_key_and_certificate,
        operations::certify::template::CertTemplate,
    },
    error::KmsError,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Maximum number of certificates followed when walking up an issuer chain.
const MAX_CHAIN_DEPTH: usize = 8;

/// The identity under which enrollment protocols use the CA key.
pub(crate) fn enrollment_user(kms: &KMS) -> UserId {
    kms.params.default_username.clone().into()
}

/// Compare two secrets in constant time (both are hashed first so that the length is not leaked).
pub(crate) fn secrets_equal(a: &str, b: &str) -> bool {
    sha256(a.as_bytes()).ct_eq(&sha256(b.as_bytes())).into()
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
            .ok_or_else(|| KmsError::ItemNotFound(format!("CA certificate not found: {uid}")))?;
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
    let user = enrollment_user(kms);
    let ca_uid = ca_uid.to_owned();
    let (private_key, certificate) = Box::pin(retrieve_issuer_private_key_and_certificate(
        None,
        Some(ObjectHandle::from(&ca_uid)),
        kms,
        &user,
    ))
    .await?;
    if private_key.state() != State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "the CA private key '{}' is not Active",
            private_key.id()
        )));
    }
    let unwrapped =
        Box::pin(kms.get_unwrapped(private_key.id(), private_key.object(), &user)).await?;
    Ok((
        kmip_certificate_to_openssl(certificate.object())?,
        kmip_private_key_to_openssl(&unwrapped)?,
    ))
}

/// Issue a certificate for `csr` from the CA `ca_uid` after enforcing `template`
/// (a baseline template when `None`). Returns the issued certificate.
pub(crate) async fn issue_from_csr(
    kms: &KMS,
    ca_uid: &str,
    csr: &X509Req,
    template: Option<&CertTemplate>,
    requested_validity_days: Option<u32>,
) -> KResult<X509> {
    let user = enrollment_user(kms);
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
    let response = kms
        .certify(
            Certify {
                unique_identifier: None,
                certificate_request_type: Some(CertificateRequestType::PKCS10),
                certificate_request_value: Some(csr.to_der()?),
                attributes: Some(attributes),
                protection_storage_masks: None,
            },
            &user,
        )
        .await?;
    let uid = response.unique_identifier.to_string();
    debug!(
        "enrollment: issued certificate {uid} from CA {uid}",
        uid = uid
    );
    let owm = kms
        .database
        .retrieve_object(&uid)
        .await
        .context("retrieve issued certificate")?
        .ok_or_else(|| KmsError::ItemNotFound(format!("issued certificate not found: {uid}")))?;
    Ok(kmip_certificate_to_openssl(owm.object())?)
}

/// Check that `cert` was issued by the CA `ca_cert` (`ca_uid`), is within its validity period
/// and is tracked by the KMS in the `Active` state (i.e. not revoked / deactivated / destroyed).
pub(crate) async fn ensure_active_certificate_of_ca(
    kms: &KMS,
    ca_uid: &str,
    ca_cert: &X509,
    cert: &X509,
) -> KResult<()> {
    let ca_public_key = ca_cert.public_key()?;
    if cert.issuer_name().to_der()? != ca_cert.subject_name().to_der()?
        || !cert.verify(&ca_public_key)?
    {
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
    let found = Box::pin(kms.database.find_certificate_by_serial(
        ca_uid,
        &serial_hex,
        kms.vendor_id(),
    ))
    .await
    .context("find_certificate_by_serial")?;
    match found {
        Some((_, State::Active, _)) => Ok(()),
        Some((uid, state, _)) => Err(KmsError::InvalidRequest(format!(
            "the certificate {uid} is in state {state} and cannot be renewed"
        ))),
        None => Err(KmsError::InvalidRequest(
            "the certificate is not known to the KMS".to_owned(),
        )),
    }
}

/// Sorted textual rendering of the `SubjectAlternativeName` entries of a CSR.
fn csr_san_set(csr: &X509Req) -> KResult<Vec<String>> {
    let der = csr.to_der()?;
    let (_, parsed) = X509CertificationRequest::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid CSR: {e}")))?;
    let mut out: Vec<String> = parsed
        .requested_extensions()
        .into_iter()
        .flatten()
        .filter_map(|ext| match ext {
            ParsedExtension::SubjectAlternativeName(san) => Some(
                san.general_names
                    .iter()
                    .map(|g| format!("{g:?}"))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect();
    out.sort();
    Ok(out)
}

/// Sorted textual rendering of the `SubjectAlternativeName` entries of a certificate.
fn cert_san_set(cert: &X509) -> KResult<Vec<String>> {
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid certificate: {e}")))?;
    let mut out: Vec<String> = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|g| format!("{g:?}"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    Ok(out)
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

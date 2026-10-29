use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_types::{LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;
use openssl::{
    pkey::{PKeyRef, Public},
    x509::{X509, X509Ref},
};

use crate::{
    core::{
        KMS,
        retrieve_object_utils::{retrieve_object_for_operation, user_has_permission},
        uid_utils::ObjectHandle,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// A stored certificate: `(uid, state, attributes)`.
pub(crate) type CertificateRecord = (String, State, Attributes);

/// Find, per serial number, the stored certificates that count for the revocation data (CRL,
/// OCSP) of the CA certificate `ca` (`ca_x509`), among the certificates linked to it.
///
/// `serials` are uppercase hex, as `BN_bn2hex` prints them (and the OCSP `CertID` parser).
///
/// A `CertificateLink` is caller-controlled (Import, `AddAttribute`): any user can link to any
/// CA a forged certificate carrying a genuine serial, or an exact copy of a genuine certificate,
/// then revoke it or keep it active. A linked certificate therefore only counts when:
/// - it names the CA as issuer and its signature verifies with the CA public key, and
/// - its owner owns the CA certificate or may `Certify` with the CA private key (i.e. could have
///   issued it), when at least one record of the serial has such an owner. Otherwise (e.g. the
///   issuer's grant was removed since) every verified record counts, so that no revocation
///   silently disappears.
pub(crate) async fn find_ca_issued_certificates(
    kms: &KMS,
    ca: &ObjectWithMetadata,
    ca_x509: &X509,
    serials: &HashSet<String>,
) -> KResult<HashMap<String, Vec<CertificateRecord>>> {
    if serials.is_empty() {
        return Ok(HashMap::new());
    }
    let ca_public_key = ca_x509.public_key()?;
    // Without its private key in the KMS, only the CA owner can have issued certificates.
    let ca_private_key = match ca.attributes().get_link(LinkType::PrivateKeyLink) {
        Some(link) => kms
            .database
            .retrieve_object_arc(&linked_id_str(&link))
            .await
            .context("retrieve the CA private key")?,
        None => None,
    };
    let mut linked = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };
    linked.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(ca.id().to_owned()),
    );
    // Cross-owner search: a CA's revocation data covers every certificate it issued.
    let candidates = kms
        .database
        .find_all(Some(&linked), None, kms.vendor_id())
        .await
        .context("search the certificates linked to the CA")?;

    let mut authority: HashMap<String, bool> = HashMap::new();
    let mut by_serial: HashMap<String, Vec<(CertificateRecord, bool)>> = HashMap::new();
    for (uid, state, attributes) in candidates {
        let Some(owm) = kms.database.retrieve_object_arc(&uid).await? else {
            continue;
        };
        let Object::Certificate(Certificate {
            certificate_value, ..
        }) = owm.object()
        else {
            continue;
        };
        let Ok(x509) = X509::from_der(certificate_value) else {
            trace!("skipping certificate '{uid}': cannot parse DER");
            continue;
        };
        let Some(serial) = x509
            .serial_number()
            .to_bn()
            .and_then(|bn| bn.to_hex_str().map(|hex| hex.to_ascii_uppercase()))
            .ok()
            .filter(|serial| serials.contains(serial))
        else {
            continue;
        };
        if !is_issued_by(&x509, ca_x509, &ca_public_key) {
            trace!(
                "ignoring certificate '{uid}': not issued by the CA '{}'",
                ca.id()
            );
            continue;
        }
        let authorized = if let Some(authorized) = authority.get(owm.owner()) {
            *authorized
        } else {
            let authorized = owm.owner_id() == ca.owner_id()
                || match &ca_private_key {
                    Some(key) => {
                        user_has_permission(
                            owm.owner_id(),
                            Some(key.as_ref()),
                            &KmipOperation::Certify,
                            kms,
                        )
                        .await?
                    }
                    None => false,
                };
            authority.insert(owm.owner().to_owned(), authorized);
            authorized
        };
        by_serial
            .entry(serial)
            .or_default()
            .push(((uid, state, attributes), authorized));
    }
    Ok(by_serial
        .into_iter()
        .map(|(serial, mut records)| {
            if records.iter().any(|(_, authorized)| *authorized) {
                records.retain(|(_, authorized)| *authorized);
            }
            (
                serial,
                records.into_iter().map(|(record, _)| record).collect(),
            )
        })
        .collect())
}

/// `true` when `cert` names `ca` as issuer and carries a valid signature from `ca_public_key`.
/// A name or signature that cannot be checked (e.g. another key type) is not the CA's.
fn is_issued_by(cert: &X509Ref, ca: &X509Ref, ca_public_key: &PKeyRef<Public>) -> bool {
    cert.issuer_name()
        .try_cmp(ca.subject_name())
        .is_ok_and(std::cmp::Ordering::is_eq)
        && cert.verify(ca_public_key).unwrap_or(false)
}

/// Retrieve the certificate associated to the given private key.
///
/// If the private key is not provided, the private key is retrieved from the certificate.
/// If the certificate id is not provided, the certificate is retrieved from the private key.
/// If none are provided, an error is returned.
///
/// Retrieval is done by following links through the public key when necessary.
pub(crate) async fn retrieve_issuer_private_key_and_certificate(
    private_key_id: Option<ObjectHandle<'_>>,
    certificate_id: Option<ObjectHandle<'_>>,
    kms: &KMS,
    user: &UserId,
) -> KResult<(ObjectWithMetadata, ObjectWithMetadata)> {
    trace!(
        "Retrieving issuer private key and certificate: private_key_id: {:?}, certificate_id: {:?}",
        private_key_id, certificate_id
    );
    if let (Some(private_key_id), Some(certificate_id)) = (private_key_id, certificate_id) {
        // Retrieve the certificate
        let certificate = Box::pin(retrieve_object_for_operation(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        let private_key = Box::pin(retrieve_object_for_operation(
            private_key_id,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        return Ok((
            Arc::unwrap_or_clone(private_key),
            Arc::unwrap_or_clone(certificate),
        ));
    }

    if let Some(private_key_id) = private_key_id {
        let private_key = Box::pin(retrieve_object_for_operation(
            private_key_id,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        let certificate = Box::pin(retrieve_certificate_for_private_key(
            &private_key,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        return Ok((Arc::unwrap_or_clone(private_key), certificate));
    }

    if let Some(certificate_id) = certificate_id {
        // Retrieve the certificate
        let certificate = Box::pin(retrieve_object_for_operation(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        let private_key = Box::pin(retrieve_private_key_for_certificate(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        return Ok((private_key, Arc::unwrap_or_clone(certificate)));
    }

    kms_bail!(KmsError::InvalidRequest(
        "Either an issuer certificate id or an issuer private key id or both must be provided"
            .to_owned(),
    ))
}

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_certificate_for_private_key(
    private_key: &ObjectWithMetadata,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> Result<ObjectWithMetadata, KmsError> {
    trace!(
        "Retrieving certificate for private key: {}",
        private_key.id()
    );
    // recover the Certificate Link inside the Private Key
    let certificate_id = private_key
        .attributes()
        .get_link(LinkType::PKCS12CertificateLink)
        .or_else(|| private_key.attributes().get_link(LinkType::CertificateLink));

    let certificate_id = if let Some(certificate_id) = certificate_id {
        trace!("found link to certificate: {}", certificate_id);
        certificate_id
    } else if ObjectHandle::from(private_key.id()).is_hsm() {
        find_certificate_linked_to_hsm_private_key(private_key, kms, user).await?
    } else {
        // Check if there is a link to a public key.
        let public_key_id = private_key
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest("No public key link found for the private key".to_owned())
            })?;
        trace!(
            "found link to public key: {}. Will get certificate link from there",
            public_key_id
        );
        Box::pin(find_link_in_public_key(
            LinkType::CertificateLink,
            &public_key_id,
            operation_type,
            kms,
            user,
        ))
        .await?
    };

    // retrieve the certificate
    let certificate_id_str = linked_id_str(&certificate_id);
    let cert_owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&*certificate_id_str),
        operation_type,
        kms,
        user,
    ))
    .await
    .with_context(|| {
        format!("could not retrieve the certificate: {certificate_id}, attached to the private key")
    })?;
    trace!(
        "Retrieved certificate: {} for private key: {}",
        cert_owm.id(),
        private_key.id()
    );
    Ok(Arc::unwrap_or_clone(cert_owm))
}

/// Find the certificate whose persisted `PrivateKeyLink` identifies an HSM key.
///
/// HSM key metadata cannot persist KMIP links, so the normal `PrivateKey` → `PublicKey` →
/// `Certificate` traversal is unavailable. Certificate links are stored in the database and
/// survive an HSM restart.
async fn find_certificate_linked_to_hsm_private_key(
    private_key: &ObjectWithMetadata,
    kms: &KMS,
    user: &UserId,
) -> KResult<LinkedObjectIdentifier> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };
    filter.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(private_key.id().to_owned()),
    );
    let certificate_ids = kms
        .database
        .find(Some(&filter), None, user, false, kms.vendor_id())
        .await?;
    match certificate_ids.as_slice() {
        [(certificate_id, _, _)] => {
            trace!(
                "found certificate {certificate_id} linked to HSM private key {}",
                private_key.id()
            );
            Ok(LinkedObjectIdentifier::TextString(certificate_id.clone()))
        }
        [] => Err(KmsError::InvalidRequest(format!(
            "No certificate linked to HSM private key '{}'",
            private_key.id()
        ))),
        _ => Err(KmsError::InvalidRequest(format!(
            "Multiple certificates are linked to HSM private key '{}'; specify the issuer certificate",
            private_key.id()
        ))),
    }
}
/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_private_key_for_certificate(
    certificate_handle: ObjectHandle<'_>,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> Result<ObjectWithMetadata, KmsError> {
    trace!(
        "Retrieving private key for certificate: certificate_handle: {:?}",
        certificate_handle
    );
    let owm = Box::pin(retrieve_object_for_operation(
        certificate_handle,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;

    let private_key_id = owm.attributes().get_link(LinkType::PrivateKeyLink);

    let private_key_id = if let Some(private_key_id) = private_key_id {
        private_key_id
    } else {
        // check if there is a link to a public key
        let public_key_id = owm
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private or public key link found for the certificate".to_owned(),
                )
            })?;
        Box::pin(find_link_in_public_key(
            LinkType::PrivateKeyLink,
            &public_key_id,
            operation_type,
            kms,
            user,
        ))
        .await?
    };
    // retrieve the private key
    let private_key_id_str = linked_id_str(&private_key_id);
    let private_key = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&*private_key_id_str),
        operation_type,
        kms,
        user,
    ))
    .await
    .with_context(|| {
        format!("could not retrieve the private key: {private_key_id} for the certificate")
    })?;
    Ok(Arc::unwrap_or_clone(private_key))
}

/// Borrow the text of a linked object identifier when it is a text string
/// (the usual case), allocating only for the numeric/enumeration forms.
pub(crate) fn linked_id_str(id: &LinkedObjectIdentifier) -> Cow<'_, str> {
    match id {
        LinkedObjectIdentifier::TextString(s) => Cow::Borrowed(s.as_str()),
        other => Cow::Owned(other.to_string()),
    }
}

async fn find_link_in_public_key(
    link_type: LinkType,
    public_key_id: &LinkedObjectIdentifier,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> Result<LinkedObjectIdentifier, KmsError> {
    // TODO: retrieve only the attributes when #88 is fixed
    let public_key_id = linked_id_str(public_key_id);
    let public_key_owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&*public_key_id),
        operation_type,
        kms,
        user,
    ))
    .await?;
    let public_key_attributes = public_key_owm.attributes();
    // retrieve the private key linked to the public key
    public_key_attributes.get_link(link_type).ok_or_else(|| {
        KmsError::InvalidRequest(format!("No {link_type:?} found in the public key"))
    })
}

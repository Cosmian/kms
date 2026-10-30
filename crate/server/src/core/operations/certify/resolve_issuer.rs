use std::sync::Arc;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
            kmip_attributes::Attributes,
            kmip_operations::Certify,
            kmip_types::{LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::{kmip_certificate_to_openssl, kmip_private_key_to_openssl},
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;
use openssl::pkey::{PKey, Public};

#[cfg(feature = "non-fips")]
use super::rfc9935;
use super::{
    issuer::{Issuer, IssuerKey},
    subject::Subject,
};
use crate::{
    core::{
        KMS,
        certificate::{
            oracle_signing::OracleSigningKey, retrieve_issuer_private_key_and_certificate,
        },
        operations::algorithm_policy::{
            enforce_kmip_algorithm_policy_for_public_key,
            enforce_kmip_algorithm_policy_for_retrieved_key,
        },
        retrieve_object_utils::retrieve_object_for_operation,
        uid_utils::ObjectHandle,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

/// Verify that the issuer private key is in the Active state before signing.
///
/// KMIP §4.57 mandates that a Deactivated key **SHALL NOT** be used for applying
/// cryptographic protection (including signing). Using a non-Active issuer key
/// to sign a certificate violates this constraint.
fn ensure_issuer_key_active(private_key: &ObjectWithMetadata) -> KResult<()> {
    if private_key.state() != State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "Certify: the issuer private key '{}' is in state '{}' — only Active keys may sign \
             certificates",
            private_key.id(),
            private_key.state()
        )));
    }
    Ok(())
}

/// Determine the issuer of the issued certificate.
/// The issuer can be recovered from different sources or be self-signed.
pub(crate) async fn get_issuer<'a>(
    subject: &'a Subject,
    kms: &KMS,
    request: &Certify,
    user: &UserId,
) -> KResult<Issuer<'a>> {
    let (issuer_certificate_id, issuer_private_key_id) =
        request
            .attributes
            .as_ref()
            .map_or((None, None), |attributes| {
                // Retrieve the issuer certificate id if provided
                let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
                // Retrieve the issuer private key id if provided
                let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
                (issuer_certificate_id, issuer_private_key_id)
            });

    // Debug logging
    if let Some(id) = &issuer_certificate_id {
        trace!("Issuer certificate id: {}", id);
    } else {
        trace!("No issuer certificate id provided");
    }
    if let Some(id) = &issuer_private_key_id {
        trace!("Issuer private key id: {}", id);
    } else {
        trace!("No issuer private key id provided");
    }

    if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
        // If no issuer is provided, the subject is self-signed
        return Box::pin(issuer_for_self_signed_certificate(subject, kms, user)).await;
    }
    // Bind the link identifiers to locals so the borrowed `ObjectHandle`s outlive the call.
    let issuer_private_key_id = issuer_private_key_id.map(|id| id.to_string());
    let issuer_certificate_id = issuer_certificate_id.map(|id| id.to_string());
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.as_ref().map(ObjectHandle::from),
        issuer_certificate_id.as_ref().map(ObjectHandle::from),
        kms,
        user,
    )
    .await?;
    // KMIP §4.57: Deactivated keys SHALL NOT be used for signing.
    ensure_issuer_key_active(&issuer_private_key)?;
    // Non-sensitive HSM keys are returned exported, sensitive ones as metadata stubs; either way
    // an HSM key always signs through the oracle, so the retrieved-key check is skipped and the
    // policy is enforced on the issuer public key below.
    if !ObjectHandle::from(issuer_private_key.id()).is_hsm() {
        enforce_kmip_algorithm_policy_for_retrieved_key(
            &kms.params,
            "Certify",
            issuer_private_key.id(),
            &issuer_private_key,
        )?;
    }
    let issuer_x509 = kmip_certificate_to_openssl(issuer_certificate.object())?;
    let issuer_key = Box::pin(load_issuer_key(
        kms,
        &issuer_private_key,
        issuer_x509.public_key()?,
        user,
    ))
    .await?;
    // The retrieved-key check trusts KMIP attributes, which may be absent (PKCS#8 import): also
    // check the real key material. HSM keys have no loaded material: the policy is checked on the
    // issuer certificate's public key.
    match &issuer_key {
        IssuerKey::Local(key) => enforce_kmip_algorithm_policy_for_public_key(
            &kms.params,
            "Certify",
            key,
            issuer_private_key.object().attributes().ok(),
        )?,
        IssuerKey::Oracle(key) => enforce_kmip_algorithm_policy_for_public_key(
            &kms.params,
            "Certify",
            &key.public_key,
            issuer_private_key.object().attributes().ok(),
        )?,
    }
    Ok(Issuer::PrivateKeyAndCertificate(
        UniqueIdentifier::TextString(issuer_certificate.id().to_owned()),
        issuer_key,
        issuer_x509,
    ))
}

/// Load the issuer signing key: in memory for database keys, by reference for HSM keys
/// (which may be non-extractable and must never be exported).
pub(crate) async fn load_issuer_key(
    kms: &KMS,
    private_key: &ObjectWithMetadata,
    issuer_public_key: PKey<Public>,
    user: &UserId,
) -> KResult<IssuerKey> {
    if let Some(key) = OracleSigningKey::for_hsm_uid(private_key.id(), issuer_public_key)? {
        return Ok(IssuerKey::Oracle(key));
    }
    // The private key may be stored in wrapped form (e.g. with a server KEK): unwrap it first.
    let unwrapped =
        Box::pin(kms.get_unwrapped(private_key.id(), private_key.object(), user)).await?;
    Ok(IssuerKey::Local(kmip_private_key_to_openssl(&unwrapped)?))
}

/// Link to the private key of `public_key`. HSM objects carry no KMIP links: the private key of
/// an HSM public key `<sk>_pk` is `<sk>`.
pub(super) fn private_key_link_of(
    public_key: &ObjectWithMetadata,
) -> Option<LinkedObjectIdentifier> {
    public_key
        .attributes()
        .get_link(LinkType::PrivateKeyLink)
        .or_else(|| {
            public_key
                .id()
                .strip_suffix(SYSTEM_TAG_PUBLIC_KEY)
                .filter(|_| ObjectHandle::from(public_key.id()).is_hsm())
                .map(|sk_uid| LinkedObjectIdentifier::TextString(sk_uid.to_owned()))
        })
}

async fn fetch_object_from_attributes(
    link_type: LinkType,
    kms: &KMS,
    attributes: &Attributes,
    user: &UserId,
) -> KResult<Option<Arc<ObjectWithMetadata>>> {
    if let Some(object_id) = attributes.get_link(link_type) {
        let object = Box::pin(retrieve_object_for_operation(
            ObjectHandle::from(&object_id.to_string()),
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;
        return Ok(Some(object));
    }
    Ok(None)
}

async fn issuer_for_self_signed_certificate<'a>(
    subject: &'a Subject,
    kms: &KMS,
    user: &UserId,
) -> KResult<Issuer<'a>> {
    match subject {
        Subject::X509Req(_, _) => {
            // the case where the private key is specified in the attributes is already covered
            kms_bail!(
                "Invalid request: a self-signed certificate cannot be created from a CSR without \
                 specifying the private key id"
            )
        }
        Subject::Certificate(unique_identifier, certificate, certificate_attributes) => {
            // the user is renewing a self-signed certificate. See if we can find
            // a linked private key
            let private_key = fetch_object_from_attributes(
                LinkType::PrivateKeyLink,
                kms,
                certificate_attributes,
                user,
            )
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key linked to the certificate found to renew it as self-signed"
                        .to_owned(),
                )
            })?;
            // KMIP §4.57: Deactivated keys SHALL NOT be used for signing.
            ensure_issuer_key_active(&private_key)?;
            let issuer_key = Box::pin(load_issuer_key(
                kms,
                &private_key,
                certificate.public_key()?,
                user,
            ))
            .await?;
            Ok(Issuer::PrivateKeyAndCertificate(
                unique_identifier.clone(),
                issuer_key,
                certificate.clone(),
            ))
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, public_key, subject_name) => {
            // the user is creating a self-signed certificate from a public key
            // try fetching the corresponding private key to sign it
            let private_key = match private_key_link_of(public_key) {
                Some(link) => Some(
                    Box::pin(retrieve_object_for_operation(
                        ObjectHandle::from(&link.to_string()),
                        KmipOperation::Certify,
                        kms,
                        user,
                    ))
                    .await?,
                ),
                None => None,
            }
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key link found to create a self-signed certificate from a public \
                     key"
                    .to_owned(),
                )
            })?;
            // KMIP §4.57: Deactivated keys SHALL NOT be used for signing.
            ensure_issuer_key_active(&private_key)?;
            let issuer_key = Box::pin(load_issuer_key(
                kms,
                &private_key,
                subject.public_key()?,
                user,
            ))
            .await?;
            // see if we can find an existing certificate to link to the public key
            let certificate = fetch_object_from_attributes(
                LinkType::CertificateLink,
                kms,
                public_key.attributes(),
                user,
            )
            .await?;
            match certificate {
                Some(certificate) => Ok(Issuer::PrivateKeyAndCertificate(
                    unique_identifier.clone(),
                    issuer_key,
                    kmip_certificate_to_openssl(certificate.object())?,
                )),
                None => Ok(Issuer::PrivateKeyAndSubjectName(
                    unique_identifier.clone(),
                    issuer_key,
                    subject_name,
                )),
            }
        }
        Subject::KeypairAndSubjectName(unique_identifier, keypair_data, subject_name) => {
            // RFC 9935: KEM keys cannot self-sign — they must be issued by a signing CA.
            #[cfg(feature = "non-fips")]
            {
                let algo = if let Object::PrivateKey(sk) = &keypair_data.private_key_object {
                    sk.key_block.cryptographic_algorithm
                } else {
                    kms_bail!(KmsError::ServerError(
                        "Expected a PrivateKey object in keypair data".to_owned()
                    ))
                };
                if !rfc9935::is_signing_capable(algo) {
                    kms_bail!(KmsError::InvalidRequest(
                        "Only signing algorithms (RSA, EC, ECDSA, Ed25519, Ed448, ML-DSA, \
                         SLH-DSA) can issue self-signed certificates. For KEM or other \
                         non-signing keys, provide issuer_private_key_id and \
                         issuer_certificate_id pointing to a signing CA."
                            .to_owned()
                    ))
                }
            }
            Ok(Issuer::PrivateKeyAndSubjectName(
                unique_identifier.clone(),
                IssuerKey::Local(kmip_private_key_to_openssl(
                    &keypair_data.private_key_object,
                )?),
                subject_name,
            ))
        }
    }
}

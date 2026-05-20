#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_operations::Certify,
        kmip_types::{LinkType, UniqueIdentifier},
    },
    cosmian_kms_crypto::openssl::{kmip_certificate_to_openssl, kmip_private_key_to_openssl},
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;

#[cfg(feature = "non-fips")]
use super::rfc9935;
use super::{issuer::Issuer, subject::Subject};
use crate::{
    core::{
        KMS, certificate::retrieve_issuer_private_key_and_certificate,
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Determine the issuer of the issued certificate.
/// The issuer can be recovered from different sources or be self-signed.
pub(super) async fn get_issuer<'a>(
    subject: &'a Subject,
    kms: &KMS,
    request: &Certify,
    user: &str,
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
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.map(|id| id.to_string()),
        issuer_certificate_id.map(|id| id.to_string()),
        kms,
        user,
    )
    .await?;
    // The private key may be stored in wrapped form (e.g. when using an HSM with a KEK).
    // Unwrap it before converting to OpenSSL format for signing.
    let unwrapped_pk = kms
        .get_unwrapped(issuer_private_key.id(), issuer_private_key.object(), user)
        .await?;
    Ok(Issuer::PrivateKeyAndCertificate(
        UniqueIdentifier::TextString(issuer_certificate.id().to_owned()),
        kmip_private_key_to_openssl(&unwrapped_pk)?,
        kmip_certificate_to_openssl(issuer_certificate.object())?,
    ))
}

async fn fetch_object_from_attributes(
    link_type: LinkType,
    kms: &KMS,
    attributes: &Attributes,
    user: &str,
) -> KResult<Option<ObjectWithMetadata>> {
    if let Some(object_id) = attributes.get_link(link_type) {
        let object = Box::pin(retrieve_object_for_operation(
            &object_id.to_string(),
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
    user: &str,
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
            let unwrapped_pk = kms
                .get_unwrapped(private_key.id(), private_key.object(), user)
                .await?;
            Ok(Issuer::PrivateKeyAndCertificate(
                unique_identifier.clone(),
                kmip_private_key_to_openssl(&unwrapped_pk)?,
                certificate.clone(),
            ))
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, public_key, subject_name) => {
            // the user is creating a self-signed certificate from a public key
            // try fetching the corresponding private key to sign it
            let private_key = fetch_object_from_attributes(
                LinkType::PrivateKeyLink,
                kms,
                public_key.attributes(),
                user,
            )
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key link found to create a self-signed certificate from a public \
                     key"
                    .to_owned(),
                )
            })?;
            let unwrapped_pk = kms
                .get_unwrapped(private_key.id(), private_key.object(), user)
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
                    kmip_private_key_to_openssl(&unwrapped_pk)?,
                    kmip_certificate_to_openssl(certificate.object())?,
                )),
                None => Ok(Issuer::PrivateKeyAndSubjectName(
                    unique_identifier.clone(),
                    kmip_private_key_to_openssl(&unwrapped_pk)?,
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
                kmip_private_key_to_openssl(&keypair_data.private_key_object)?,
                subject_name,
            ))
        }
    }
}

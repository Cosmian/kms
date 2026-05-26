use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_operations::{Certify, CertifyResponse},
            kmip_types::{LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::trace;

use super::{
    build_certificate::build_and_sign_certificate, resolve_issuer::get_issuer,
    resolve_subject::get_subject, subject::Subject,
};
use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

/// Certify a certificate.
/// This operation is used to issue a certificate based on a public key, a CSR or a key pair.
/// The certificate can be self-signed or signed by another certificate.
pub(crate) async fn certify(
    kms: &KMS,
    request: Certify,
    user: &str,
    privileged_users: Option<Vec<String>>,
) -> KResult<CertifyResponse> {
    trace!("{}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // To generate the certificate, we really want to compose the following functions
    // generate_x509(get_issuer(get_subject)))
    // The code below could be rewritten in a more functional way
    // but this would require manipulating some sort of Monad Transformer
    let subject = Box::pin(get_subject(kms, &request, user, privileged_users)).await?;
    trace!("Subject name: {:?}", subject.subject_name());
    let issuer = Box::pin(get_issuer(&subject, kms, &request, user)).await?;
    trace!("Issuer Subject name: {:?}", issuer.subject_name());
    let (certificate, tags, attributes) =
        build_and_sign_certificate(kms.vendor_id(), &issuer, &subject, request)?;

    let (operations, unique_identifier) = match subject {
        Subject::X509Req(unique_identifier, _) | Subject::Certificate(unique_identifier, _, _) => {
            trace!("Certify X509Req or Certificate:{unique_identifier}");
            (
                vec![
                    // upsert the certificate
                    AtomicOperation::Upsert((
                        unique_identifier.to_string(),
                        certificate,
                        attributes,
                        Some(tags),
                        State::Active,
                    )),
                ],
                unique_identifier,
            )
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, from_public_key, _) => {
            trace!(
                "Certify PublicKeyAndSubjectName:{unique_identifier}: public key: \
                 {from_public_key}"
            );
            // update the public key attributes with a link to the certificate
            let mut public_key_attributes = from_public_key.attributes().to_owned();
            public_key_attributes.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::from(unique_identifier.clone()),
            );
            // update the certificate attributes with a link to the public key
            let mut certificate_attributes = attributes.clone();
            certificate_attributes.set_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::TextString(from_public_key.id().to_owned()),
            );
            // update the link to the private for the certificate
            if let Some(private_key_id) = public_key_attributes.get_link(LinkType::PrivateKeyLink) {
                certificate_attributes.set_link(LinkType::PrivateKeyLink, private_key_id);
            }
            (
                vec![
                    // upsert the certificate
                    AtomicOperation::Upsert((
                        unique_identifier.to_string(),
                        certificate,
                        certificate_attributes,
                        Some(tags),
                        State::Active,
                    )),
                    // update the public key
                    AtomicOperation::UpdateObject((
                        from_public_key.id().to_owned(),
                        from_public_key.object().to_owned(),
                        public_key_attributes,
                        None,
                    )),
                ],
                unique_identifier,
            )
        }
        Subject::KeypairAndSubjectName(unique_identifier, mut keypair_data, _) => {
            trace!(
                "Certify KeypairAndSubjectName:{unique_identifier} : keypair data: {keypair_data}"
            );
            // update the private key attributes with the public key identifier
            keypair_data.private_key_object.attributes_mut()?.set_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::from(keypair_data.public_key_id.clone()),
            );
            // update the private key attributes with a link to the certificate
            keypair_data.private_key_object.attributes_mut()?.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::from(unique_identifier.clone()),
            );
            // update the public key attributes with a link to the private key
            keypair_data.public_key_object.attributes_mut()?.set_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::from(keypair_data.private_key_id.clone()),
            );
            // update the public key attributes with a link to the certificate
            keypair_data.public_key_object.attributes_mut()?.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::from(unique_identifier.clone()),
            );
            // update the certificate attributes with a link to the public key
            let mut certificate_attributes = attributes.clone();
            certificate_attributes.set_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::from(keypair_data.public_key_id.clone()),
            );
            // update the certificate attributes with a link to the private key
            certificate_attributes.set_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::from(keypair_data.private_key_id.clone()),
            );
            if let Some(cert_links) = certificate_attributes.link.as_ref() {
                for link in cert_links {
                    trace!("Certificate attribute link: {}", link);
                }
            } else {
                trace!("Certificate attributes links: None");
            }
            (
                vec![
                    // upsert the private key
                    AtomicOperation::Upsert((
                        keypair_data.private_key_id.to_string(),
                        keypair_data.private_key_object.clone(),
                        keypair_data.private_key_object.attributes()?.clone(),
                        Some(keypair_data.private_key_tags),
                        State::Active,
                    )),
                    // upsert the public key
                    AtomicOperation::Upsert((
                        keypair_data.public_key_id.to_string(),
                        keypair_data.public_key_object.clone(),
                        keypair_data.public_key_object.attributes()?.clone(),
                        Some(keypair_data.public_key_tags),
                        State::Active,
                    )),
                    // upsert the certificate
                    AtomicOperation::Upsert((
                        unique_identifier.to_string(),
                        certificate,
                        certificate_attributes,
                        Some(tags),
                        State::Active,
                    )),
                ],
                unique_identifier,
            )
        }
    };

    // perform DB operations
    kms.database.atomic(user, &operations).await?;

    Ok(CertifyResponse { unique_identifier })
}

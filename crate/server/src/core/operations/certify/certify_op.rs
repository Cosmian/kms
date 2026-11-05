use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            extra::VENDOR_ATTR_X509_EXTENSION,
            kmip_objects::ObjectType,
            kmip_operations::{Certify, CertifyResponse},
            kmip_types::{LinkType, LinkedObjectIdentifier, VendorAttributeValue},
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::trace;

use super::{
    build_certificate::build_and_sign_certificate,
    resolve_issuer::{get_issuer, private_key_link_of},
    resolve_subject::get_subject,
    subject::Subject,
};
use crate::{
    config::ServerParams,
    core::{
        KMS, ObjectHandle,
        operations::{
            algorithm_policy::{
                enforce_kmip_algorithm_policy_for_csr, enforce_kmip_algorithm_policy_for_public_key,
            },
            key_ops::ObjectLifecycleExt,
        },
    },
    middlewares::UserId,
    result::KResult,
};

/// Certify a certificate.
/// This operation is used to issue a certificate based on a public key, a CSR or a key pair.
/// The certificate can be self-signed or signed by another certificate.
pub(crate) async fn certify(
    kms: &KMS,
    mut request: Certify,
    user: &UserId,
) -> KResult<CertifyResponse> {
    normalize_kmip1_x509_extension(&mut request, kms.vendor_id());
    Box::pin(certify_for_owner(kms, request, user, user)).await
}

/// KMIP 1.x clients carry the X.509 extension config as the custom attribute
/// `y-<vendor_id>::x509-extension` (KMIP 1.4 §3.39; the same name the KMIP 1.x attribute
/// conversion emits for a vendor attribute), converted to a `KMIP1` vendor attribute.
/// Rewrite it to the vendor attribute the certify pipeline reads. The pipeline expects a
/// `ByteString`, so a `TextString` value (the natural 1.x form of the config) is converted.
fn normalize_kmip1_x509_extension(request: &mut Certify, vendor_id: &str) {
    let kmip1_name = format!("y-{vendor_id}::{VENDOR_ATTR_X509_EXTENSION}");
    if let Some(vas) = request
        .attributes
        .as_mut()
        .and_then(|a| a.vendor_attributes.as_mut())
    {
        for va in vas
            .iter_mut()
            .filter(|va| va.vendor_identification == "KMIP1" && va.attribute_name == kmip1_name)
        {
            vendor_id.clone_into(&mut va.vendor_identification);
            VENDOR_ATTR_X509_EXTENSION.clone_into(&mut va.attribute_name);
            if let VendorAttributeValue::TextString(text) = &mut va.attribute_value {
                va.attribute_value =
                    VendorAttributeValue::ByteString(std::mem::take(text).into_bytes());
            }
        }
    }
}

/// Certify: the certified key (and a PKCS#10 request's signature) must satisfy the active
/// algorithm policy; the issuer key is checked when it is resolved.
fn enforce_subject_algorithm_policy(params: &ServerParams, subject: &Subject) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let hint = match subject {
        Subject::X509Req(_, req) => return enforce_kmip_algorithm_policy_for_csr(params, req),
        Subject::PublicKeyAndSubjectName(_, owm, _) => owm.object().attributes().ok(),
        Subject::KeypairAndSubjectName(_, keypair, _) => {
            keypair.public_key_object.attributes().ok()
        }
        Subject::Certificate(..) => None,
    };
    let key = subject.public_key()?;
    enforce_kmip_algorithm_policy_for_public_key(params, "Certify", &key, hint)
}

/// [`certify`] with the authorization checks (issuer `Certify` grant, `Create` right) evaluated
/// for `user` while the created objects are stored, in the same atomic write, under `owner`.
///
/// Used by EST/SCEP enrollment: the reserved enrollment service identity is authorized through
/// its explicit grant on the CA, and the issued certificate belongs to the CA owner, who can
/// therefore revoke and manage it without any post-issuance grant.
pub(crate) async fn certify_for_owner(
    kms: &KMS,
    request: Certify,
    user: &UserId,
    owner: &UserId,
) -> KResult<CertifyResponse> {
    // The CSR is not logged: a SCEP PKCSReq carries the enrollment challengePassword in it.
    trace!(
        "Certify: unique_identifier={:?}, request type={:?}, request value: {} bytes",
        request.unique_identifier,
        request.certificate_request_type,
        request
            .certificate_request_value
            .as_ref()
            .map_or(0, Vec::len)
    );
    KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

    // To generate the certificate, we really want to compose the following functions
    // generate_x509(get_issuer(get_subject)))
    // The code below could be rewritten in a more functional way
    // but this would require manipulating some sort of Monad Transformer
    let subject = Box::pin(get_subject(kms, &request, user)).await?;
    enforce_subject_algorithm_policy(&kms.params, &subject)?;
    trace!("Subject name: {:?}", subject.subject_name());
    let issuer = Box::pin(get_issuer(&subject, kms, &request, user)).await?;
    trace!("Issuer Subject name: {:?}", issuer.subject_name());
    let (certificate, tags, mut attributes) = Box::pin(build_and_sign_certificate(
        kms,
        &issuer,
        &subject,
        request,
        kms.params.kms_public_url.as_deref(),
    ))
    .await?;
    // KMIP 2.1 §4.57 transition 1: a new object starts Pre-Active unless the request
    // carries an Activation Date that has already occurred.
    let activation_date = attributes.activation_date;
    let state = if activation_date.is_some_and(|d| d <= time::OffsetDateTime::now_utc()) {
        State::Active
    } else {
        State::PreActive
    };
    attributes.state = Some(state);

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
                        state,
                    )),
                ],
                unique_identifier,
            )
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, from_public_key, _) => {
            trace!("Certify public-key subject {unique_identifier}");
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
            // update the link to the private key for the certificate
            let is_hsm_key = ObjectHandle::from(from_public_key.id()).is_hsm();
            let private_key_id = private_key_link_of(&from_public_key);
            if let Some(private_key_id) = private_key_id {
                certificate_attributes.set_link(LinkType::PrivateKeyLink, private_key_id);
            }
            // upsert the certificate
            let mut operations = vec![AtomicOperation::Upsert((
                unique_identifier.to_string(),
                certificate,
                certificate_attributes,
                Some(tags),
                state,
            ))];
            // Update the public key, unless it is an HSM object: it cannot store KMIP links
            // (`HsmStore::update_object` is a no-op) and the batch runs on the certificate's store.
            if !is_hsm_key {
                operations.push(AtomicOperation::UpdateObject((
                    from_public_key.id().to_owned(),
                    from_public_key.object().to_owned(),
                    public_key_attributes,
                    None,
                )));
            }
            (operations, unique_identifier)
        }
        Subject::KeypairAndSubjectName(unique_identifier, mut keypair_data, _) => {
            trace!("Certify key-pair subject {unique_identifier}");
            // Initialise lifecycle attributes (state, initial_date, activation_date, digest)
            // on both keys.  Without this call, `initial_date` is `None` in the stored
            // `attributes_json`, which causes `is_due_for_rotation` to return `false`
            // forever — the auto-rotation scheduler silently skips the key.
            // The keys follow the request's Activation Date like the certificate.
            keypair_data
                .private_key_object
                .setup_with_lifecycle(ObjectType::PrivateKey, activation_date)?;
            keypair_data
                .private_key_object
                .attributes_mut()?
                .initialize_never_extractable();
            keypair_data
                .public_key_object
                .setup_with_lifecycle(ObjectType::PublicKey, activation_date)?;
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
            let private_key_attrs = keypair_data.private_key_object.attributes()?.clone();
            let public_key_attrs = keypair_data.public_key_object.attributes()?.clone();
            (
                vec![
                    // upsert the private key
                    AtomicOperation::Upsert((
                        keypair_data.private_key_id.to_string(),
                        keypair_data.private_key_object,
                        private_key_attrs,
                        Some(keypair_data.private_key_tags),
                        state,
                    )),
                    // upsert the public key
                    AtomicOperation::Upsert((
                        keypair_data.public_key_id.to_string(),
                        keypair_data.public_key_object,
                        public_key_attrs,
                        Some(keypair_data.public_key_tags),
                        state,
                    )),
                    // upsert the certificate
                    AtomicOperation::Upsert((
                        unique_identifier.to_string(),
                        certificate,
                        certificate_attributes,
                        Some(tags),
                        state,
                    )),
                ],
                unique_identifier,
            )
        }
    };

    kms.constraints.check_new_objects(&operations)?;
    // perform DB operations
    kms.database.atomic(owner, &operations).await?;

    Ok(CertifyResponse { unique_identifier })
}

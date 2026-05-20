use std::{cmp::min, collections::HashSet, default::Default};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
#[cfg(not(feature = "non-fips"))]
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::fips::{
            FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN,
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_ECC_MASK_ECDH,
            FIPS_PUBLIC_ECC_MASK_SIGN, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_RSA_MASK,
        },
        kmip_types::CryptographicAlgorithm,
    },
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip,
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            extra::{VENDOR_ATTR_X509_EXTENSION, tagging::SYSTEM_TAG_CERTIFICATE},
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
            kmip_operations::{Certify, CertifyResponse, CreateKeyPair},
            kmip_types::{
                CertificateRequestType, KeyFormatType, LinkType, LinkedObjectIdentifier,
                UniqueIdentifier, VendorAttributeValue,
            },
        },
    },
    cosmian_kms_crypto::openssl::{
        certificate_attributes_to_subject_name, kmip_certificate_to_openssl,
        kmip_private_key_to_openssl, openssl_certificate_to_kmip,
        openssl_x509_to_certificate_attributes, x509_extensions,
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{debug, info, trace};
#[cfg(feature = "non-fips")]
use openssl::x509::extension::KeyUsage;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    hash::MessageDigest,
    pkey::Id,
    sha::Sha1,
    x509::{X509, X509Req},
};

use crate::{
    core::{
        KMS,
        certificate::retrieve_issuer_private_key_and_certificate,
        operations::{
            certify::{
                issuer::Issuer,
                subject::{KeyPairData, Subject},
            },
            create_key_pair::generate_key_pair,
        },
        retrieve_object_utils::{retrieve_object_for_operation, user_has_permission},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

mod issuer;
mod rfc9608;
#[cfg(feature = "non-fips")]
mod rfc9881;
#[cfg(feature = "non-fips")]
mod rfc9909;
#[cfg(feature = "non-fips")]
mod rfc9935;
mod subject;

const X509_VERSION3: i32 = 2;

/// Certify a certificate
/// This operation is used to issue a certificate based on a public key, a CSR or a key pair
/// The certificate can be self-signed or signed by another certificate
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

#[cfg(not(feature = "non-fips"))]
fn cryptographic_usage_mask_private_key(
    cryptographic_algorithm: CryptographicAlgorithm,
) -> KResult<CryptographicUsageMask> {
    Ok(match cryptographic_algorithm {
        CryptographicAlgorithm::RSA => FIPS_PRIVATE_RSA_MASK,
        CryptographicAlgorithm::ECDH => FIPS_PRIVATE_ECC_MASK_ECDH,
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => FIPS_PRIVATE_ECC_MASK_SIGN,
        CryptographicAlgorithm::EC => FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
        c => kms_bail!(KmsError::InvalidRequest(format!(
            "Cryptographic algorithm not supported for private key in FIPS mode: {c}"
        ))),
    })
}

#[cfg(not(feature = "non-fips"))]
fn cryptographic_usage_mask_public_key(
    cryptographic_algorithm: CryptographicAlgorithm,
) -> KResult<CryptographicUsageMask> {
    Ok(match cryptographic_algorithm {
        CryptographicAlgorithm::RSA => FIPS_PUBLIC_RSA_MASK,
        CryptographicAlgorithm::ECDH => FIPS_PUBLIC_ECC_MASK_ECDH,
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => FIPS_PUBLIC_ECC_MASK_SIGN,
        CryptographicAlgorithm::EC => FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        c => kms_bail!(KmsError::InvalidRequest(format!(
            "Cryptographic algorithm not supported for private key in FIPS mode: {c}"
        ))),
    })
}

/// Determine the subject of the issued certificate
/// The subject can be recovered from different sources:
/// - a public key and a subject name
/// - a certificate
/// - a key pair and a subject name
/// - a CSR
async fn get_subject(
    kms: &KMS,
    request: &Certify,
    user: &str,

    privileged_users: Option<Vec<String>>,
) -> KResult<Subject> {
    // Did the user provide a CSR?
    if let Some(pkcs10_bytes) = request.certificate_request_value.as_ref() {
        let x509_req = match &request
            .certificate_request_type
            .as_ref()
            .unwrap_or(&CertificateRequestType::PEM)
        {
            CertificateRequestType::PEM => X509Req::from_pem(pkcs10_bytes),
            CertificateRequestType::PKCS10 => X509Req::from_der(pkcs10_bytes),
            CertificateRequestType::CRMF => kms_bail!(KmsError::InvalidRequest(
                "Certificate Request Type CRMF not supported".to_owned()
            )),
        }?;
        let certificate_id = request
            .attributes
            .as_ref()
            .and_then(|attributes| attributes.unique_identifier.clone())
            .unwrap_or_default();
        // see if there is a link to a private key (in case of self-signed cert)
        return Ok(Subject::X509Req(certificate_id, x509_req));
    }

    // no CSR provided. Was the reference to an existing certificate or public key provided?
    let public_key = if let Some(request_id) = &request.unique_identifier {
        if let Ok(owm) = Box::pin(retrieve_object_for_operation(
            &request_id.to_string(),
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await
        {
            let object_type = owm.object().object_type();
            match object_type {
                // If the user passed a certificate, attempt to renew it
                ObjectType::Certificate => {
                    let certificate_id = request
                        .attributes
                        .as_ref()
                        .and_then(|attributes| attributes.unique_identifier.clone())
                        .unwrap_or_else(|| request_id.clone());
                    return Ok(Subject::Certificate(
                        certificate_id,
                        kmip_certificate_to_openssl(owm.object())?,
                        owm.attributes().to_owned(),
                    ));
                }
                // If the user passed a public key, it is a new certificate signing this public key
                ObjectType::PublicKey => Some(owm),
                // Invalid request
                x => kms_bail!("Invalid Certify request for object type {x:?}"),
            }
        } else {
            return Err(KmsError::ItemNotFound(request_id.to_string()));
        }
    } else {
        None
    };

    // This is a request based on a Subject Name
    let attributes = request.attributes.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify from Subject: the attributes specifying the the subject name are missing"
                .to_owned(),
        )
    })?;
    let subject_name = certificate_attributes_to_subject_name(
        attributes.certificate_attributes.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest(
                "Certify from Subject: the subject name is not found in the attributes".to_owned(),
            )
        })?,
    )?;

    // If we have a public key, we can create a certificate from it
    if let Some(mut public_key) = public_key {
        // The public key may be stored in wrapped form (e.g. when using a KEK).
        // Unwrap it before using it for certificate creation.
        let unwrapped_object = kms
            .get_unwrapped(public_key.id(), public_key.object(), user)
            .await?;
        public_key.set_object(unwrapped_object);
        return Ok(Subject::PublicKeyAndSubjectName(
            attributes.unique_identifier.clone().unwrap_or_default(),
            public_key,
            subject_name,
        ));
    }

    // If we do not have a public key, we need to create a key pair

    // For creation of an object, check that user has create access-right
    // The `Create` right implicitly grants permission for Create, Import, and Register operations.
    if let Some(users) = privileged_users {
        let has_permission = user_has_permission(
            user,
            None,
            &cosmian_kmip::kmip_2_1::KmipOperation::Create,
            kms,
        )
        .await?;

        if !has_permission && !users.iter().any(|u| u == user) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    let sk_uid = UniqueIdentifier::default();
    let pk_uid = UniqueIdentifier::default();
    // We expect the attributes to contain the cryptographic algorithm and parameters
    #[cfg(not(feature = "non-fips"))]
    let (private_attributes, public_attributes) = {
        let cryptographic_algorithm = attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "Keypair creation: the cryptographic algorithm is missing".to_owned(),
            )
        })?;
        let private_attributes = Attributes {
            cryptographic_usage_mask: Some(cryptographic_usage_mask_private_key(
                cryptographic_algorithm,
            )?),
            ..Default::default()
        };
        let public_attributes = Attributes {
            cryptographic_usage_mask: Some(cryptographic_usage_mask_public_key(
                cryptographic_algorithm,
            )?),
            ..Default::default()
        };
        (Some(private_attributes), Some(public_attributes))
    };
    #[cfg(feature = "non-fips")]
    let (private_attributes, public_attributes) = (None, None);
    let create_key_pair_request = CreateKeyPair {
        common_attributes: Some(attributes.to_owned()),
        private_key_attributes: private_attributes,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
        public_key_attributes: public_attributes,
    };
    info!("Creating key pair for certification - private key: {sk_uid}, public key: {pk_uid}");
    let key_pair = generate_key_pair(
        kms.vendor_id(),
        create_key_pair_request,
        &sk_uid.to_string(),
        &pk_uid.to_string(),
    )?;
    info!("Key pair created for certification");

    Ok(Subject::KeypairAndSubjectName(
        attributes.unique_identifier.clone().unwrap_or_default(),
        KeyPairData {
            private_key_id: sk_uid,
            private_key_object: key_pair.private_key().to_owned(),
            private_key_tags: key_pair
                .private_key()
                .attributes()?
                .get_tags(kms.vendor_id()),
            public_key_id: pk_uid,
            public_key_object: key_pair.public_key().to_owned(),
            public_key_tags: key_pair
                .public_key()
                .attributes()?
                .get_tags(kms.vendor_id()),
        },
        subject_name,
    ))
}

/// Determine the issuer of the issued certificate.
/// The issuer can be recovered from different sources or be self-signed:
async fn get_issuer<'a>(
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
            // Only signing-capable algorithms can issue self-signed certificates.
            // KEM / hybrid-KEM keys must be signed by a separate CA.
            #[cfg(feature = "non-fips")]
            if let Object::PrivateKey(sk) = &keypair_data.private_key_object {
                if !is_signing_capable(sk.key_block.cryptographic_algorithm) {
                    kms_bail!(KmsError::InvalidRequest(
                        "Only signing algorithms (RSA, EC, ECDSA, Ed25519, Ed448, ML-DSA, \
                         SLH-DSA) can issue self-signed certificates. For KEM or other \
                         non-signing keys, provide issuer_private_key_id and \
                         issuer_certificate_id pointing to a signing CA."
                            .to_owned()
                    ))
                }
            } else {
                kms_bail!(KmsError::ServerError(
                    "Expected a PrivateKey object in keypair data".to_owned()
                ))
            }
            Ok(Issuer::PrivateKeyAndSubjectName(
                unique_identifier.clone(),
                kmip_private_key_to_openssl(&keypair_data.private_key_object)?,
                subject_name,
            ))
        }
    }
}

fn create_subject_key_identifier_value(subject: &Subject) -> KResult<Asn1Integer> {
    let pk = subject.public_key()?;
    let spki_der = pk.public_key_to_der()?;
    let mut sha1 = Sha1::default();
    sha1.update(&spki_der);
    let mut serial_number_bytes = sha1.finish().to_vec();

    // Ensure the serial number is always positive by clearing the high bit of the first byte.
    // This prevents ASN.1 DER encoding from adding a leading 0x00 byte for negative numbers,
    // which would make the serial number 21 bytes instead of 20 bytes.
    // RFC 5280 Section 4.1.2.2 allows serial numbers up to 20 octets.
    *serial_number_bytes
        .get_mut(0)
        .ok_or_else(|| KmsError::ServerError("SHA1 digest returned empty bytes".to_owned()))? &=
        0x7F;

    let serial_number = openssl::asn1::Asn1Integer::from_bn(
        openssl::bn::BigNum::from_slice(&serial_number_bytes)?.as_ref(),
    )?;
    Ok(serial_number)
}

/// RFC 9881 (ML-DSA) / RFC 9935 (ML-KEM): extract the KMIP `CryptographicAlgorithm` from a
/// Subject that represents a fresh keypair or standalone public key. Returns `None` for
/// CSR-based and re-certification cases (they already carry RFC-compliant extensions).
#[cfg(feature = "non-fips")]
const fn subject_pqc_algorithm(subject: &Subject) -> Option<CryptographicAlgorithm> {
    match subject {
        Subject::PublicKeyAndSubjectName(_, owm, _) => {
            if let Object::PublicKey(pk) = owm.object() {
                pk.key_block.cryptographic_algorithm
            } else {
                None
            }
        }
        Subject::KeypairAndSubjectName(_, keypair, _) => {
            if let Object::PublicKey(pk) = &keypair.public_key_object {
                pk.key_block.cryptographic_algorithm
            } else {
                None
            }
        }
        Subject::X509Req(..) | Subject::Certificate(..) => None,
    }
}

/// Return `true` when the vendor extension-config attribute marks this certificate as a CA
/// (`basicConstraints=CA:TRUE` or `basicConstraints=critical,CA:TRUE`).
///
/// This is used in `build_and_sign_certificate` to decide whether to include the
/// `keyCertSign` and `cRLSign` bits in the RFC-mandated PQC `keyUsage` extension,
/// and to enforce RFC 9608 §3 (noRevAvail MUST NOT appear in CA certificates).
/// RFC 5280 §4.2.1.3 requires `keyCertSign` when `keyUsage` is present *and* the
/// certificate will be used to verify certificate signatures in path validation.
/// OpenSSL's `X509_verify_cert` enforces this check.
fn extension_config_is_ca(attributes: &Attributes, vendor_id: &str) -> bool {
    attributes
        .vendor_attributes
        .as_ref()
        .and_then(|vas| {
            vas.iter().find(|va| {
                va.vendor_identification == vendor_id
                    && va.attribute_name == VENDOR_ATTR_X509_EXTENSION
            })
        })
        .and_then(|va| {
            if let VendorAttributeValue::ByteString(ref b) = va.attribute_value {
                Some(String::from_utf8_lossy(b).to_uppercase())
            } else {
                None
            }
        })
        .is_some_and(|upper| upper.contains("CA:TRUE"))
}

/// Shared helper: build the critical `keyUsage` extension for PQC **signing** algorithms
/// (ML-DSA per RFC 9881 §5, SLH-DSA per RFC 9909 §6).
///
/// - End-entity: `digitalSignature` (critical)
/// - CA (`is_ca=true`): `digitalSignature | keyCertSign | cRLSign` (critical)
///
/// Called by [`rfc9881::apply_extensions`] and [`rfc9909::apply_extensions`].
#[cfg(feature = "non-fips")]
fn pqc_signing_key_usage(is_ca: bool) -> KResult<openssl::x509::X509Extension> {
    let mut ku = KeyUsage::new();
    ku.critical().digital_signature();
    if is_ca {
        // RFC 5280 §4.2.1.3: keyCertSign required for CA certs with keyUsage present.
        ku.key_cert_sign().crl_sign();
    }
    Ok(ku.build()?)
}

/// Return `true` if the given algorithm is signing-capable and can issue self-signed
/// certificates. Non-signing algorithms (KEM, DH, etc.) must be signed by a separate CA.
///
/// This is a general RFC 5280 §4.2.1.3 requirement: a certificate's subject key must be
/// able to produce the signature that covers the TBS certificate.
#[cfg(feature = "non-fips")]
const fn is_signing_capable(algo: Option<CryptographicAlgorithm>) -> bool {
    matches!(
        algo,
        Some(
            CryptographicAlgorithm::RSA
                | CryptographicAlgorithm::EC
                | CryptographicAlgorithm::ECDSA
                | CryptographicAlgorithm::Ed25519
                | CryptographicAlgorithm::Ed448
                | CryptographicAlgorithm::MLDSA_44
                | CryptographicAlgorithm::MLDSA_65
                | CryptographicAlgorithm::MLDSA_87
                | CryptographicAlgorithm::SLHDSA_SHA2_128s
                | CryptographicAlgorithm::SLHDSA_SHA2_128f
                | CryptographicAlgorithm::SLHDSA_SHA2_192s
                | CryptographicAlgorithm::SLHDSA_SHA2_192f
                | CryptographicAlgorithm::SLHDSA_SHA2_256s
                | CryptographicAlgorithm::SLHDSA_SHA2_256f
                | CryptographicAlgorithm::SLHDSA_SHAKE_128s
                | CryptographicAlgorithm::SLHDSA_SHAKE_128f
                | CryptographicAlgorithm::SLHDSA_SHAKE_192s
                | CryptographicAlgorithm::SLHDSA_SHAKE_192f
                | CryptographicAlgorithm::SLHDSA_SHAKE_256s
                | CryptographicAlgorithm::SLHDSA_SHAKE_256f
        )
    )
}

/// RFC 9881 §5 / RFC 9909 §6 / RFC 9935 §5 — auto-add the RFC-mandated critical keyUsage
/// extension for fresh PQC key certifications.
///
/// Dispatches to the per-RFC submodule based on the algorithm family.
/// CSR-based and re-certification cases already carry extensions from the original object,
/// so this only fires when `subject_pqc_algorithm` returns `Some`.
#[cfg(feature = "non-fips")]
fn apply_pqc_key_usage(
    x509_builder: &mut openssl::x509::X509Builder,
    subject: &Subject,
    attributes: &Attributes,
    vendor_id: &str,
) -> KResult<()> {
    if let Some(algo) = subject_pqc_algorithm(subject) {
        let is_ca = extension_config_is_ca(attributes, vendor_id);
        match algo {
            CryptographicAlgorithm::MLDSA_44
            | CryptographicAlgorithm::MLDSA_65
            | CryptographicAlgorithm::MLDSA_87 => {
                rfc9881::apply_extensions(x509_builder, is_ca)?;
            }
            CryptographicAlgorithm::SLHDSA_SHA2_128s
            | CryptographicAlgorithm::SLHDSA_SHA2_128f
            | CryptographicAlgorithm::SLHDSA_SHA2_192s
            | CryptographicAlgorithm::SLHDSA_SHA2_192f
            | CryptographicAlgorithm::SLHDSA_SHA2_256s
            | CryptographicAlgorithm::SLHDSA_SHA2_256f
            | CryptographicAlgorithm::SLHDSA_SHAKE_128s
            | CryptographicAlgorithm::SLHDSA_SHAKE_128f
            | CryptographicAlgorithm::SLHDSA_SHAKE_192s
            | CryptographicAlgorithm::SLHDSA_SHAKE_192f
            | CryptographicAlgorithm::SLHDSA_SHAKE_256s
            | CryptographicAlgorithm::SLHDSA_SHAKE_256f => {
                rfc9909::apply_extensions(x509_builder, is_ca)?;
            }
            CryptographicAlgorithm::MLKEM_512
            | CryptographicAlgorithm::MLKEM_768
            | CryptographicAlgorithm::MLKEM_1024
            | CryptographicAlgorithm::X25519MLKEM768
            | CryptographicAlgorithm::X448MLKEM1024
            | CryptographicAlgorithm::ConfigurableKEM => {
                rfc9935::apply_extensions(x509_builder)?;
            }
            _ => {} // RSA, EC, EdDSA — no automatic PQC keyUsage
        }
    }
    Ok(())
}

/// RFC 5280 §4.2 — apply user-supplied X.509v3 extensions from the vendor attribute CNF.
///
/// Returns `true` if the user-supplied config contains a `crlDistributionPoints` entry
/// (needed by `apply_no_rev_avail` to decide whether to auto-add `noRevAvail`).
fn apply_user_extensions(
    x509_builder: &mut openssl::x509::X509Builder,
    attributes: &mut Attributes,
    vendor_id: &str,
    issuer: &Issuer,
) -> KResult<bool> {
    if let Some(extensions) = attributes.remove_x509_extension_file(vendor_id) {
        let extensions_as_str = String::from_utf8(extensions)?;
        debug!("OpenSSL Extensions: {}", extensions_as_str);
        let has_cdp = extensions_as_str.contains("crlDistributionPoints");
        let context = x509_builder.x509v3_context(issuer.certificate(), None);
        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
        Ok(has_cdp)
    } else {
        Ok(false)
    }
}

/// RFC 9608 §2–§3 — delegate to [`rfc9608::apply_extensions`].
fn apply_no_rev_avail(
    x509_builder: &mut openssl::x509::X509Builder,
    issuer: &Issuer,
    attributes: &Attributes,
    vendor_id: &str,
    has_cdp: bool,
) -> KResult<()> {
    rfc9608::apply_extensions(x509_builder, issuer, attributes, vendor_id, has_cdp)
}

fn build_and_sign_certificate(
    vendor_id: &str,
    issuer: &Issuer,
    subject: &Subject,
    request: Certify,
) -> KResult<(Object, HashSet<String>, Attributes)> {
    debug!("Building and signing certificate");
    // recover the attributes
    let mut attributes = request.attributes.unwrap_or_default();
    // Set the object type
    attributes.object_type = Some(ObjectType::Certificate);

    // remove any link that helped identify the issuer
    // these will be properly re-added later
    attributes.remove_link(LinkType::CertificateLink);
    attributes.remove_link(LinkType::PrivateKeyLink);
    attributes.remove_link(LinkType::PublicKeyLink);

    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder()?;

    // Handle the subject name and public key
    x509_builder.set_version(X509_VERSION3)?;
    x509_builder.set_subject_name(subject.subject_name())?;
    x509_builder.set_pubkey(subject.public_key()?.as_ref())?;

    // Handle expiration dates
    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;
    // retrieve the number of days for the validity of the certificate
    let mut number_of_days =
        u32::try_from(attributes.remove_validity_days(vendor_id).unwrap_or(365))?;
    trace!("Number of days: {}", number_of_days);

    // the number of days cannot exceed that of the issuer certificate
    if let Some(issuer_not_after) = issuer.not_after() {
        trace!("Issuer certificate not after: {issuer_not_after}");
        let days = u32::try_from(now.diff(issuer_not_after)?.days)?;
        number_of_days = min(days, number_of_days);
    }
    x509_builder.set_not_before(now.as_ref())?;
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;

    // add subject extensions (from CSR or existing certificate)
    subject
        .extensions()?
        .into_iter()
        .try_for_each(|extension| x509_builder.append_extension(extension))?;

    // RFC 9881 §5 / RFC 9909 §6 / RFC 9935 §5: auto-add PQC keyUsage
    #[cfg(feature = "non-fips")]
    apply_pqc_key_usage(&mut x509_builder, subject, &attributes, vendor_id)?;

    // RFC 5280 §4.2: user-supplied extensions from vendor attribute CNF
    let has_cdp = apply_user_extensions(&mut x509_builder, &mut attributes, vendor_id, issuer)?;

    // RFC 9608 §2–§3: auto-add noRevAvail for self-signed end-entity certs
    apply_no_rev_avail(&mut x509_builder, issuer, &attributes, vendor_id, has_cdp)?;

    // The digest must match the *issuer's signing key* type, not the subject key.
    // RSA and EC (ECDSA) require an explicit external digest; EdDSA and PQC algorithms
    // (ML-DSA, SLH-DSA) handle their digest internally and must receive a null digest.
    let digest = match issuer.private_key().id() {
        Id::RSA | Id::EC => MessageDigest::sha256(),
        _ => MessageDigest::null(), // EdDSA, ML-DSA, SLH-DSA — internal digest
    };

    // Set the issuer name and private key
    x509_builder.set_issuer_name(issuer.subject_name())?;
    x509_builder.set_serial_number(create_subject_key_identifier_value(subject)?.as_ref())?;
    x509_builder.sign(issuer.private_key(), digest)?;

    let x509 = x509_builder.build();

    // Process the tags
    let mut tags = attributes.remove_tags(vendor_id).unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }
    // add subject tags if any
    tags.extend(subject.tags(vendor_id).iter().cloned());
    // add the certificate "system" tag
    tags.insert(SYSTEM_TAG_CERTIFICATE.to_owned());

    // link the certificate to the issuer certificate
    attributes.set_link(
        LinkType::CertificateLink,
        issuer.unique_identifier().clone().into(),
    );

    // remove cryptographic information from the certificate attributes
    attributes.cryptographic_algorithm = None;
    attributes.cryptographic_length = None;
    attributes.cryptographic_parameters = None;
    attributes.cryptographic_usage_mask = None;
    attributes.cryptographic_domain_parameters = None;
    // Set the key format type to X509
    attributes.key_format_type = Some(KeyFormatType::X509);

    // Add certificate attributes
    let certificate_attributes = openssl_x509_to_certificate_attributes(&x509);
    attributes.certificate_attributes = Some(certificate_attributes);

    Ok((
        openssl_certificate_to_kmip(&x509).map_err(KmsError::from)?,
        tags,
        attributes,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    #[allow(
        clippy::expect_used,
        clippy::missing_asserts_for_indexing,
        clippy::indexing_slicing
    )]
    fn test_serial_number_without_fix_creates_21_bytes() {
        // This test verifies the BUG: without clearing the high bit,
        // ASN.1 DER encoding adds a leading 0x00 byte to indicate positive numbers,
        // resulting in 21-byte serial numbers instead of 20 bytes.

        // Create a serial number with high bit set (0x83 = 10000011 in binary)
        let serial_with_high_bit = vec![
            0x83, 0xE9, 0x9B, 0x1A, 0xCA, 0x8A, 0xB0, 0xDD, 0x65, 0xE3, 0x79, 0xB6, 0x28, 0x99,
            0xAD, 0x73, 0x9E, 0x16, 0x33, 0x82,
        ];

        // WITHOUT the fix - directly convert bytes to Asn1Integer (this would be the buggy code)
        let bn = openssl::bn::BigNum::from_slice(&serial_with_high_bit)
            .expect("Failed to create BigNum from slice");
        let asn1_int_buggy = openssl::asn1::Asn1Integer::from_bn(bn.as_ref())
            .expect("Failed to create Asn1Integer from BigNum");

        // Create a minimal X.509 certificate to see how the serial number is encoded
        let rsa = openssl::rsa::Rsa::generate(2048).expect("Failed to generate RSA key");
        let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("Failed to create PKey");

        let mut x509_builder =
            openssl::x509::X509::builder().expect("Failed to create X509 builder");
        x509_builder
            .set_serial_number(asn1_int_buggy.as_ref())
            .expect("Failed to set serial number");
        x509_builder
            .set_pubkey(&pkey)
            .expect("Failed to set public key");
        x509_builder
            .set_not_before(
                openssl::asn1::Asn1Time::days_from_now(0)
                    .expect("Failed to create Asn1Time")
                    .as_ref(),
            )
            .expect("Failed to set not_before");
        x509_builder
            .set_not_after(
                openssl::asn1::Asn1Time::days_from_now(365)
                    .expect("Failed to create Asn1Time")
                    .as_ref(),
            )
            .expect("Failed to set not_after");
        x509_builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .expect("Failed to sign certificate");

        let cert = x509_builder.build();
        let cert_der = cert.to_der().expect("Failed to get certificate DER");

        // Parse the DER to find the serial number field
        // X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        // tbsCertificate: SEQUENCE { [version], serialNumber, ... }

        // Look for the INTEGER tag (0x02) which should contain our serial number
        // The serial number appears early in the certificate
        let mut found_21_byte_serial = false;
        for window in cert_der.windows(3) {
            // Look for INTEGER tag (0x02) with length 0x15 (21 bytes)
            if window[0] == 0x02 && window[1] == 0x15 && window[2] == 0x00 {
                found_21_byte_serial = true;
                break;
            }
        }

        assert!(
            found_21_byte_serial,
            "Certificate DER should contain a 21-byte serial number field (0x02 0x15 0x00 ...) \
             when high bit is set. This demonstrates the bug: ASN.1 adds a 0x00 prefix byte."
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_serial_number_length() {
        // Test that serial numbers are always 20 bytes or less
        // This verifies the fix for the issue where some certificates
        // had 21-byte serial numbers with a leading 0x00 byte

        // Create test data with high bit set (would trigger the issue before the fix)
        let test_cases = vec![
            // Serial that starts with high bit set (0x83 = 10000011)
            vec![
                0x83, 0xE9, 0x9B, 0x1A, 0xCA, 0x8A, 0xB0, 0xDD, 0x65, 0xE3, 0x79, 0xB6, 0x28, 0x99,
                0xAD, 0x73, 0x9E, 0x16, 0x33, 0x82,
            ],
            // Serial that starts with high bit NOT set (0x04)
            vec![
                0x04, 0xC5, 0xB6, 0x49, 0x2B, 0xE0, 0x8F, 0xF2, 0x16, 0x98, 0x1E, 0xBF, 0x65, 0x02,
                0x50, 0xD7, 0xA9, 0xE1, 0xDC, 0xC5,
            ],
            // All high bits set
            vec![
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
        ];

        for (idx, mut serial_bytes) in test_cases.into_iter().enumerate() {
            // Apply the fix (same as in create_subject_key_identifier_value)
            if let Some(first_byte) = serial_bytes.get_mut(0) {
                *first_byte &= 0x7F;
            }

            // Create BigNum and then Asn1Integer
            let bn = openssl::bn::BigNum::from_slice(&serial_bytes)
                .expect("Failed to create BigNum from slice");
            let asn1_int = openssl::asn1::Asn1Integer::from_bn(bn.as_ref())
                .expect("Failed to create Asn1Integer from BigNum");

            // Get the DER encoding
            let der = asn1_int
                .to_bn()
                .expect("Failed to convert Asn1Integer to BigNum")
                .to_vec();

            // The serial number should be at most 20 bytes
            let first_byte = serial_bytes.first().copied().unwrap_or(0);
            assert!(
                der.len() <= 20,
                "Test case {idx}: Serial number is {} bytes (expected <= 20 bytes). \
                 First byte after fix: 0x{first_byte:02X}",
                der.len(),
            );

            // Verify the high bit is not set in the first byte
            assert_eq!(
                first_byte & 0x80,
                0,
                "Test case {idx}: High bit should not be set in first byte",
            );
        }
    }
}

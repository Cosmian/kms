use std::{cmp::min, collections::HashSet, default::Default};

#[cfg(feature = "fips")]
use cosmian_kmip::{
    crypto::{
        elliptic_curves::{
            FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN,
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
            FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        },
        rsa::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK},
    },
    kmip::kmip_types::{CryptographicAlgorithm, CryptographicUsageMask},
};
use cosmian_kmip::{
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Certify, CertifyResponse, CreateKeyPair},
        kmip_types::{
            Attributes, CertificateAttributes, CertificateRequestType, KeyFormatType, LinkType,
            LinkedObjectIdentifier, StateEnumeration, UniqueIdentifier,
        },
        KmipOperation,
    },
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, openssl_certificate_to_kmip,
    },
};
use cosmian_kms_server_database::{AtomicOperation, ExtraStoreParams, ObjectWithMetadata};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    hash::MessageDigest,
    sha::Sha1,
    x509::{X509Req, X509},
};
use tracing::{debug, info, trace};

use crate::{
    core::{
        certificate::retrieve_issuer_private_key_and_certificate,
        operations::{
            certify::{
                issuer::Issuer,
                subject::{KeyPairData, Subject},
            },
            create_key_pair::generate_key_pair_and_tags,
        },
        retrieve_object_utils::retrieve_object_for_operation,
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

mod issuer;
mod subject;

const X509_VERSION3: i32 = 2;

/// Certify a certificate
/// This operation is used to issue a certificate based on a public key, a CSR or a key pair
/// The certificate can be self-signed or signed by another certificate
pub(crate) async fn certify(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<CertifyResponse> {
    trace!("Certify: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // To generate the certificate, we really want to compose the following functions
    // generate_x509(get_issuer(get_subject)))
    // The code below could be rewritten in a more functional way
    // but this would require manipulating some sort of Monad Transformer
    let subject = get_subject(kms, &request, user, params).await?;
    trace!("Subject name: {:?}", subject.subject_name());
    let issuer = get_issuer(&subject, kms, &request, user, params).await?;
    trace!("Issuer Subject name: {:?}", issuer.subject_name());
    let (certificate, tags, attributes) = build_and_sign_certificate(&issuer, &subject, request)?;

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
                        StateEnumeration::Active,
                    )),
                ],
                unique_identifier,
            )
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, from_public_key, _) => {
            trace!(
                "Certify PublicKeyAndSubjectName:{unique_identifier} : public key: \
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
                        StateEnumeration::Active,
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
            trace!(
                "Certificate attributes links: {:?}",
                certificate_attributes.link
            );
            (
                vec![
                    // upsert the private key
                    AtomicOperation::Upsert((
                        keypair_data.private_key_id.to_string(),
                        keypair_data.private_key_object.clone(),
                        keypair_data.private_key_object.attributes()?.clone(),
                        Some(keypair_data.private_key_tags),
                        StateEnumeration::Active,
                    )),
                    // upsert the public key
                    AtomicOperation::Upsert((
                        keypair_data.public_key_id.to_string(),
                        keypair_data.public_key_object.clone(),
                        keypair_data.public_key_object.attributes()?.clone(),
                        Some(keypair_data.public_key_tags),
                        StateEnumeration::Active,
                    )),
                    // upsert the certificate
                    AtomicOperation::Upsert((
                        unique_identifier.to_string(),
                        certificate,
                        certificate_attributes,
                        Some(tags),
                        StateEnumeration::Active,
                    )),
                ],
                unique_identifier,
            )
        }
    };

    // perform DB operations
    kms.database.atomic(user, &operations, params).await?;

    Ok(CertifyResponse { unique_identifier })
}

#[cfg(feature = "fips")]
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

#[cfg(feature = "fips")]
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
    params: Option<&ExtraStoreParams>,
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
        return Ok(Subject::X509Req(certificate_id, x509_req))
    }

    // no CSR provided. Was the reference to an existing certificate or public key provided?
    let public_key = if let Some(request_id) = &request.unique_identifier {
        if let Ok(owm) = retrieve_object_for_operation(
            &request_id.to_string(),
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
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
                    ))
                }
                //If the user passed a public key, it is a new certificate signing this public key
                ObjectType::PublicKey => Some(owm),
                // Invalid request
                x => kms_bail!("Invalid Certify request for object type {x:?}"),
            }
        } else {
            None
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
    let subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Certify from Subject: the subject name is not found in the attributes".to_owned(),
            )
        })?
        .subject_name()?;

    // If we have a public key, we can create a certificate from it
    if let Some(public_key) = public_key {
        return Ok(Subject::PublicKeyAndSubjectName(
            attributes.unique_identifier.clone().unwrap_or_default(),
            public_key,
            subject_name,
        ))
    }

    // If we do not have a public key, we need to create a key pair
    let sk_uid = UniqueIdentifier::default();
    let pk_uid = UniqueIdentifier::default();
    // We expect the attributes to contain the cryptographic algorithm and parameters
    #[cfg(feature = "fips")]
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
    #[cfg(not(feature = "fips"))]
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
    let (key_pair, sk_tags, pk_tags) = generate_key_pair_and_tags(
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
            private_key_tags: sk_tags,
            public_key_id: pk_uid,
            public_key_object: key_pair.public_key().to_owned(),
            public_key_tags: pk_tags,
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
    params: Option<&ExtraStoreParams>,
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
    trace!(
        "Issuer certificate id: {issuer_certificate_id:?}, issuer private key id: \
         {issuer_private_key_id:?}"
    );
    if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
        // If no issuer is provided, the subject is self-signed
        return issuer_for_self_signed_certificate(subject, kms, user, params).await;
    }
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.map(|id| id.to_string()),
        issuer_certificate_id.map(|id| id.to_string()),
        kms,
        user,
        params,
    )
    .await?;
    Ok(Issuer::PrivateKeyAndCertificate(
        UniqueIdentifier::TextString(issuer_certificate.id().to_owned()),
        kmip_private_key_to_openssl(issuer_private_key.object())?,
        kmip_certificate_to_openssl(issuer_certificate.object())?,
    ))
}

async fn fetch_object_from_attributes(
    link_type: LinkType,
    kms: &KMS,
    attributes: &Attributes,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<Option<ObjectWithMetadata>> {
    if let Some(object_id) = attributes.get_link(link_type) {
        let object = retrieve_object_for_operation(
            &object_id.to_string(),
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok(Some(object));
    }
    Ok(None)
}

async fn issuer_for_self_signed_certificate<'a>(
    subject: &'a Subject,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
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
                params,
            )
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key linked to the certificate found to renew it as self-signed"
                        .to_owned(),
                )
            })?;
            Ok(Issuer::PrivateKeyAndCertificate(
                unique_identifier.clone(),
                kmip_private_key_to_openssl(private_key.object())?,
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
                params,
            )
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key link found to create a self-signed certificate from a public \
                     key"
                    .to_owned(),
                )
            })?;
            // see if we can find an existing certificate to link to the public key
            let certificate = fetch_object_from_attributes(
                LinkType::CertificateLink,
                kms,
                public_key.attributes(),
                user,
                params,
            )
            .await?;
            match certificate {
                Some(certificate) => Ok(Issuer::PrivateKeyAndCertificate(
                    unique_identifier.clone(),
                    kmip_private_key_to_openssl(private_key.object())?,
                    kmip_certificate_to_openssl(certificate.object())?,
                )),
                None => Ok(Issuer::PrivateKeyAndSubjectName(
                    unique_identifier.clone(),
                    kmip_private_key_to_openssl(private_key.object())?,
                    subject_name,
                )),
            }
        }
        Subject::KeypairAndSubjectName(unique_identifier, keypair_data, subject_name) => {
            // the user is creating a self-signed certificate from a key pair
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
    let serial_number_bytes = sha1.finish().to_vec();

    let serial_number = openssl::asn1::Asn1Integer::from_bn(
        openssl::bn::BigNum::from_slice(&serial_number_bytes)?.as_ref(),
    )?;
    Ok(serial_number)
}

fn build_and_sign_certificate(
    issuer: &Issuer,
    subject: &Subject,
    request: Certify,
) -> KResult<(Object, HashSet<String>, Attributes)> {
    debug!("Building and signing certificate");
    // recover the attributes
    let mut attributes = request.attributes.unwrap_or_default();

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
        u32::try_from(attributes.extract_requested_validity_days()?.unwrap_or(365))?;
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

    // add subject extensions
    subject
        .extensions()?
        .into_iter()
        .try_for_each(|extension| x509_builder.append_extension(extension))?;

    // Extensions supplied using an extension attribute
    // This requires knowing the issuer certificate
    if let Some(extensions) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION)
    {
        let extensions_as_str = String::from_utf8(extensions.to_vec())?;
        debug!("OpenSSL Extensions: {}", extensions_as_str);
        let context = x509_builder.x509v3_context(issuer.certificate(), None);
        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
    }

    // Set the issuer name and private key
    x509_builder.set_issuer_name(issuer.subject_name())?;
    x509_builder.set_serial_number(create_subject_key_identifier_value(subject)?.as_ref())?;
    x509_builder.sign(issuer.private_key(), MessageDigest::sha256())?;

    let x509 = x509_builder.build();

    // Process the tags
    let mut tags = attributes.remove_tags().unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }
    // add subject tags if any
    tags.extend(subject.tags().iter().cloned());
    // add the certificate "system" tag
    tags.insert("_cert".to_owned());

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
    let certificate_attributes = CertificateAttributes::from(&x509);
    attributes.certificate_attributes = Some(Box::new(certificate_attributes));

    Ok((
        openssl_certificate_to_kmip(&x509).map_err(KmsError::from)?,
        tags,
        attributes,
    ))
}

use std::{cmp::min, collections::HashSet};

use cloudproof::reexport::crypto_core::reexport::x509_cert::request;
use cosmian_kmip::{
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Certify, CertifyResponse},
        kmip_types::{
            Attributes, CertificateAttributes, CertificateRequestType, LinkType,
            LinkedObjectIdentifier, StateEnumeration, UniqueIdentifier,
        },
    },
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_certificate_to_kmip,
    },
    KmipError::Default,
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    x509::{X509Name, X509NameRef, X509Ref, X509Req, X509},
};
use tracing::trace;
use uuid::Uuid;

use crate::{
    core::{
        certificate::retrieve_issuer_private_key_and_certificate,
        extra_database_params::ExtraDatabaseParams,
        operations::certify::{
            from_csr::create_certificate_from_csr, from_existing::renew_certificate,
            from_public_key::create_certificate_from_public_key,
            from_subject::create_certificate_from_subject, issuer::Issuer, subject::Subject,
        },
        KMS,
    },
    database::{
        object_with_metadata::ObjectWithMetadata, retrieve_object_for_operation, AtomicOperation,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

mod from_csr;
mod from_public_key;
mod from_subject;

mod from_existing;
mod issuer;
mod subject;

const X509_VERSION3: i32 = 2;

pub async fn certify(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    trace!("Certify: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // sign(generate_x509(get_issuer(get_subject))

    // There are 3 possibles cases:
    // 1. A certificate creation: a CSR is provided
    // 2. A certificate renewal: the certificate id is provided and the certificate exists
    // 2. A certificate creation: all other cases

    if request.certificate_request_value.is_some() {
        return create_certificate_from_csr(kms, request, user, params).await;
    }
    if let Some(certificate_id) = &request.unique_identifier {
        if let Ok(owm) = retrieve_object_for_operation(
            &certificate_id.to_string(),
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await
        {
            let object_type = owm.object.object_type();
            return match object_type {
                // If the user passed a certificate, attempt to renew it
                ObjectType::Certificate => renew_certificate(owm, kms, request, user, params).await,
                //If the user passed a public key, it is a new certificate
                ObjectType::PublicKey => {
                    create_certificate_from_public_key(owm, kms, request, user, params).await
                }
                // Invalid reauest
                x => Err(kms_error!("Invalid Certify request for object type {x:?}")),
            };
        }
        // self-signed certificate with the given id
        return create_certificate_from_subject(certificate_id, kms, request, user, params).await;
    }
    // Create a self-signed certificate with a random UUID
    let certificate_id = UniqueIdentifier::TextString(Uuid::new_v4().to_string());
    create_certificate_from_subject(certificate_id, kms, request, user, params).await
}

async fn get_subject(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
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
                "Certificate Request Type CRMF not supported".to_string()
            )),
        }?;
        return Ok(Subject::from_x509_req(x509_req))
    }

    if let Some(certificate_id) = &request.unique_identifier {
        if let Ok(owm) = retrieve_object_for_operation(
            &certificate_id.to_string(),
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await
        {
            let object_type = owm.object.object_type();
            return match object_type {
                // If the user passed a certificate, attempt to renew it
                ObjectType::Certificate => {
                    let x509_cert =
                        kmip_certificate_to_openssl(&owm.object).map_err(KmsError::from)?;
                    let subject_name = x509_cert.subject_name();
                    let public_key = x509_cert.public_key().map_err(KmsError::from)?;
                    return Ok(Subject::from_subject_name_and_public_key(
                        subject_name,
                        public_key,
                        None,
                        None,
                    ))
                }
                //If the user passed a public key, it is a new certificate
                ObjectType::PublicKey => {
                    create_certificate_from_public_key(owm, kms, request, user, params).await
                }
                // Invalid reauest
                x => Err(kms_error!("Invalid Certify request for object type {x:?}")),
            };
        }
        // self-signed certificate with the given id
        return create_certificate_from_subject(certificate_id, kms, request, user, params).await;
    }

    let attributes = request.attributes.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify from Subject: the attributes specifying the the subject name are missing"
                .to_string(),
        )
    })?;
    let subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Certify from Subject: the subject name is not found in the attributes".to_string(),
            )
        })?
        .subject_name()?;

    Ok(Subject::from_subject_name_and_public_key(
        subject_name,
        kmip_public_key_to_openssl(&public_key.object)?,
        None,
        None,
    ))
}

// async fn generate_x509(
//     issuer: Option<Issuer>,
//     kms: &KMS,
//     request: Certify,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
// ) -> KResult<X509> {
//     // Did the user provide a CSR?
//     if let Some(pkcs10_bytes) = request.certificate_request_value.as_ref() {
//         let x509_req = match &request
//             .certificate_request_type
//             .as_ref()
//             .unwrap_or(&CertificateRequestType::PEM)
//         {
//             CertificateRequestType::PEM => X509Req::from_pem(pkcs10_bytes),
//             CertificateRequestType::PKCS10 => X509Req::from_der(pkcs10_bytes),
//             CertificateRequestType::CRMF => kms_bail!(KmsError::InvalidRequest(
//                 "Certificate Request Type CRMF not supported".to_string()
//             )),
//         }?;
//
//
//         return Ok(x509_req)
//     }
//
//     // no CSR provided. Was the reference to an existing certificate provided?
//     if let Some(certificate_id) = &request.unique_identifier {
//         if let Ok(owm) = retrieve_object_for_operation(
//             &certificate_id.to_string(),
//             ObjectOperationType::Certify,
//             kms,
//             user,
//             params,
//         )
//             .await
//         {
//             let object_type = owm.object.object_type();
//             return match object_type {
//                 // If the user passed a certificate, attempt to renew it
//                 ObjectType::Certificate => {
//                     let kmip_certificate_to_openssl(&owm.object).map_err(KmsError::from)
//                     renew_certificate(owm, kms, request, user, params).await,
//                 }
//                 //If the user passed a public key, it is a new certificate
//                 ObjectType::PublicKey => {
//                     create_certificate_from_public_key(owm, kms, request, user, params).await
//                 }
//                 // Invalid reauest
//                 x => Err(kms_error!("Invalid Certify request for object type {x:?}")),
//             };
//         }
//         // self-signed certificate with the given id
//         return create_certificate_from_subject(certificate_id, kms, request, user, params).await;
//     }
//
//     todo!("Handle self-signed certificates")
// }

async fn get_issuer(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Option<Issuer>> {
    let attributes = match request.attributes {
        Some(attributes) => attributes,
        None => return Ok(None),
    };
    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
    // Retrieve the issuer certificate and the issuer private key
    if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
        todo!("Handle self-signed certificates")
    }
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.map(|id| id.to_string()),
        issuer_certificate_id.map(|id| id.to_string()),
        kms,
        user,
        params,
    )
    .await?;
    // convert to openssl
    let issuer_pkey = kmip_private_key_to_openssl(&issuer_private_key.object)?;
    let issuer_x509 = kmip_certificate_to_openssl(&issuer_certificate.object)?;
    Ok(Some(Issuer::from_x509(
        UniqueIdentifier::TextString(issuer_certificate.id),
        issuer_pkey,
        issuer_x509,
    )))
}

// Helper method
async fn certificate_from_subject_and_pk(
    subject_name: X509Name,
    public_key: PKey<Public>,
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<(UniqueIdentifier, Object)> {
    let mut attributes = request.attributes.ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify with CSR: the attributes specifying the issuer private key is (and/or \
             certificate is) are missing"
                .to_string(),
        )
    })?;

    // Retrieve and remove tags from attributes
    // They will be added again later
    let mut tags = attributes.remove_tags().unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }

    let issuer = issuer_from_attributes(&attributes, kms, user, params)
        .await?
        .unwrap_or_else(|| {
            // Self -sign cer: the issuer is itself
            Issuer::from_subject_name_and_expiry_days(
                subject_name.clone(),
                Asn1TimeRef::default(),
                36500,
            )
        });

    // Handle expiration dates
    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;
    // retrieve the number of days for the validity of the certificate
    // the number of days cannot exceed that of the issuer certificate
    let number_of_days = min(
        issuer_not_after.diff(&now)?.days as usize,
        attributes
            .extract_requested_validity_days()?
            .unwrap_or(3650),
    );

    let issued_certificate = build_and_sign_certificate(
        &mut tags,
        &mut attributes,
        &issuer,
        now,
        number_of_days,
        subject_name,
        public_key,
    )?;

    // Use provided certificate id if any
    let issued_certificate_id = request
        .unique_identifier
        .unwrap_or(UniqueIdentifier::TextString(Uuid::new_v4().to_string()));

    Ok((issued_certificate_id, issued_certificate))
}

async fn issuer_from_attributes<'a>(
    attributes: &Attributes,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Option<Issuer>> {
    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
    // Retrieve the issuer certificate and the issuer private key
    if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
        return Ok(None);
    }
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.map(|id| id.to_string()),
        issuer_certificate_id.map(|id| id.to_string()),
        kms,
        user,
        params,
    )
    .await?;
    // convert to openssl
    let issuer_pkey = kmip_private_key_to_openssl(&issuer_private_key.object)?;
    let issuer_x509 = kmip_certificate_to_openssl(&issuer_certificate.object)?;
    Ok(Some(Issuer::from_x509(
        UniqueIdentifier::TextString(issuer_certificate.id),
        issuer_pkey,
        issuer_x509,
    )))
}

fn build_and_sign_certificate(
    tags: &mut HashSet<String>,
    attributes: &mut Attributes,
    issuer: &Issuer,
    not_before: Asn1Time,
    number_of_days: usize,
    subject_name: X509Name,
    certificate_public_key: PKey<Public>,
) -> Result<Object, KmsError> {
    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(X509_VERSION3)?;
    x509_builder.set_subject_name(subject_name.as_ref())?;
    x509_builder.set_pubkey(certificate_public_key.as_ref())?;
    x509_builder.set_not_before(not_before.as_ref())?;
    // Sign the X509 struct with the PKey struct.
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days as u32)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;
    x509_builder.set_issuer_name(&issuer.subject_name)?;
    x509_builder.sign(&*issuer.private_key, MessageDigest::sha256())?;

    // Extensions
    if let Some(extensions) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION)
    {
        let extensions_as_str = String::from_utf8(extensions.to_vec())?;
        let issuer_x509 = issuer.x509.as_ref().map(|x509| x509.as_ref());
        let context = x509_builder.x509v3_context(issuer_x509, None);
        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
    }

    let x509 = x509_builder.build();

    // link the certificate to the issuer certificate
    attributes.add_link(
        LinkType::CertificateLink,
        issuer.certificate_id.clone().into(),
    );

    // add the certificate "system" tag
    tags.insert("_cert".to_string());
    let certificate_attributes = CertificateAttributes::from(&x509);
    attributes.certificate_attributes = Some(Box::new(certificate_attributes));

    openssl_certificate_to_kmip(&x509).map_err(KmsError::from)
}

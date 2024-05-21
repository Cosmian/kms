use std::{cmp::min, collections::HashSet, default::Default};

use cloudproof::reexport::crypto_core::reexport::x509_cert::request;
use cosmian_kmip::{
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Certify, CertifyResponse, CreateKeyPair},
        kmip_types::{
            Attributes, CertificateAttributes, CertificateRequestType, LinkType,
            LinkedObjectIdentifier, StateEnumeration, UniqueIdentifier,
        },
    },
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_certificate_to_kmip,
    },
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
        operations::{
            certify::{
                from_csr::create_certificate_from_csr,
                from_existing::renew_certificate,
                from_public_key::create_certificate_from_public_key,
                from_subject::create_certificate_from_subject,
                issuer::Issuer,
                subject::{KeyPairData, Subject},
            },
            create_key_pair::generate_key_pair_and_tags,
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

    // sign(generate_x509(add_extensions(get_issuer(get_subject)))
    let subject = get_subject(kms, request, user, params).await?;

    // // There are 3 possibles cases:
    // // 1. A certificate creation: a CSR is provided
    // // 2. A certificate renewal: the certificate id is provided and the certificate exists
    // // 2. A certificate creation: all other cases
    //
    // if request.certificate_request_value.is_some() {
    //     return create_certificate_from_csr(kms, request, user, params).await;
    // }
    // if let Some(certificate_id) = &request.unique_identifier {
    //     if let Ok(owm) = retrieve_object_for_operation(
    //         &certificate_id.to_string(),
    //         ObjectOperationType::Certify,
    //         kms,
    //         user,
    //         params,
    //     )
    //     .await
    //     {
    //         let object_type = owm.object.object_type();
    //         return match object_type {
    //             // If the user passed a certificate, attempt to renew it
    //             ObjectType::Certificate => renew_certificate(owm, kms, request, user, params).await,
    //             //If the user passed a public key, it is a new certificate
    //             ObjectType::PublicKey => {
    //                 create_certificate_from_public_key(owm, kms, request, user, params).await
    //             }
    //             // Invalid reauest
    //             x => Err(kms_error!("Invalid Certify request for object type {x:?}")),
    //         };
    //     }
    //     // self-signed certificate with the given id
    //     return create_certificate_from_subject(certificate_id, kms, request, user, params).await;
    // }
    // // Create a self-signed certificate with a random UUID
    // let certificate_id = UniqueIdentifier::TextString(Uuid::new_v4().to_string());
    // create_certificate_from_subject(certificate_id, kms, request, user, params).await
    //
    todo!()
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
        let certificate_id = request.unique_identifier.clone().unwrap_or_default();
        // see if there is a link to a private key (in case of self-signed cert)
        return Ok(Subject::X509Req(certificate_id, x509_req))
    }

    // no CSR provided. Was the reference to an existing certificate or public key provided?
    let public_key = if let Some(certificate_id) = &request.unique_identifier {
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
            match object_type {
                // If the user passed a certificate, attempt to renew it
                ObjectType::Certificate => {
                    return Ok(Subject::Certificate(certificate_id.clone(), owm))
                }
                //If the user passed a public key, it is a new certificate signing this publick key
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

    if let Some(public_key) = public_key {
        return Ok(Subject::PublicKeyAndSubjectName(
            request.unique_identifier.unwrap_or_default(),
            public_key,
            subject_name,
        ))
    }

    // If we do not have a public key, we need to create a key pair
    let sk_uid = UniqueIdentifier::default();
    let pk_uid = UniqueIdentifier::default();
    // We expect the attributes to contain the cryptographic algorithm and parameters
    let create_key_pair_request = CreateKeyPair {
        common_attributes: Some(attributes.to_owned()),
        private_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
        public_key_attributes: None,
    };
    let (key_pair, sk_tags, pk_tags) = generate_key_pair_and_tags(
        create_key_pair_request,
        &sk_uid.to_string(),
        &pk_uid.to_string(),
    )?;

    Ok(Subject::KeypairAndSubjectName(
        request.unique_identifier.unwrap_or_default(),
        KeyPairData {
            key_pair,
            secret_key_id: sk_uid,
            secret_key_tags: sk_tags,
            public_key_id: pk_uid,
            public_key_tags: pk_tags,
        },
        subject_name,
    ))
}

async fn get_issuer(
    subject: Subject,
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Issuer> {
    let (issuer_certificate_id, issuer_private_key_id) = match &request.attributes {
        Some(attributes) => {
            // Retrieve the issuer certificate id if provided
            let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
            // Retrieve the issuer private key id if provided
            let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
            (issuer_certificate_id, issuer_private_key_id)
        }
        None => (None, None),
    };

    if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
        // If no issuer is provided, the subject is self-signed
        return issuer_for_self_signed_certificate(subject, kms, request, user, params).await;
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
        UniqueIdentifier::TextString(issuer_certificate.id.clone()),
        issuer_private_key,
        issuer_certificate,
    ))
}

async fn fetch_object_from_attributes(
    link_type: LinkType,
    kms: &KMS,
    attributes: &Attributes,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Option<ObjectWithMetadata>> {
    if let Some(object_id) = attributes.get_link(link_type) {
        let object = retrieve_object_for_operation(
            &object_id.to_string(),
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok(Some(object));
    }
    Ok(None)
}

async fn issuer_for_self_signed_certificate(
    subject: &Subject,
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Issuer> {
    match subject {
        Subject::X509Req(_, _) => {
            // the case where the private key is is specified in the attributes is already covered
            kms_bail!(
                "Invalid request: a self-signed certificate cannot be created from a CSR without \
                 specifying the private key id"
            )
        }
        Subject::Certificate(unique_identifier, certificate) => {
            // the user is renewing a self-signed certificate. See if we can find
            // a linked private key
            let private_key =
                fetch_private_key_from_attributes(kms, &owm.object.attributes, user, params)
                    .await?
                    .ok_or_else(|| {
                        KmsError::InvalidRequest(
                            "No private key link found to renew the self-signed certificate"
                                .to_string(),
                        )
                    })?;
            Ok(Issuer::PrivateKeyAndCertificate(
                unique_identifier.clone(),
                private_key,
                certificate.clone(),
            ))
        }
        Subject::PublicKeyAndSubjectName(unique_identifier, public_key, subjec_name) => {
            // the user is creating a self-signed certificate from a public key
            // try fetching the corresponding private key to sign it
            let private_key = fetch_object_from_attributes(
                LinkType::PrivateKeyLink,
                kms,
                &public_key.attributes,
                user,
                params,
            )
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private key link found to create a self-signed certificate from a public \
                     key"
                    .to_string(),
                )
            })?;
            // see if we can find an existing certificate to link to the public key
            let certificate = fetch_object_from_attributes(
                LinkType::CertificateLink,
                kms,
                &public_key.attributes,
                user,
                params,
            ))?;
            Ok(Issuer::PrivateKeyAndCertificate(
                unique_identifier.clone(),
                private_key,
                public_key.clone(),
            ))
        }
        Subject::KeypairAndSubjectName(_, _, _) => {}
    }
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

// // Helper method
// async fn certificate_from_subject_and_pk(
//     subject_name: X509Name,
//     public_key: PKey<Public>,
//     kms: &KMS,
//     request: Certify,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
// ) -> KResult<(UniqueIdentifier, Object)> {
//     let mut attributes = request.attributes.ok_or_else(|| {
//         KmsError::InvalidRequest(
//             "Certify with CSR: the attributes specifying the issuer private key is (and/or \
//              certificate is) are missing"
//                 .to_string(),
//         )
//     })?;
//
//     // Retrieve and remove tags from attributes
//     // They will be added again later
//     let mut tags = attributes.remove_tags().unwrap_or_default();
//     if !tags.is_empty() {
//         Attributes::check_user_tags(&tags)?;
//     }
//
//     let issuer = issuer_from_attributes(&attributes, kms, user, params)
//         .await?
//         .unwrap_or_else(|| {
//             // Self -sign cer: the issuer is itself
//             Issuer::from_subject_name_and_expiry_days(
//                 subject_name.clone(),
//                 Asn1TimeRef::default(),
//                 36500,
//             )
//         });
//
//     // Handle expiration dates
//     // Create a new Asn1Time object for the current time
//     let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;
//     // retrieve the number of days for the validity of the certificate
//     // the number of days cannot exceed that of the issuer certificate
//     let number_of_days = min(
//         issuer_not_after.diff(&now)?.days as usize,
//         attributes
//             .extract_requested_validity_days()?
//             .unwrap_or(3650),
//     );
//
//     let issued_certificate = build_and_sign_certificate(
//         &mut tags,
//         &mut attributes,
//         &issuer,
//         now,
//         number_of_days,
//         subject_name,
//         public_key,
//     )?;
//
//     // Use provided certificate id if any
//     let issued_certificate_id = request
//         .unique_identifier
//         .unwrap_or(UniqueIdentifier::TextString(Uuid::new_v4().to_string()));
//
//     Ok((issued_certificate_id, issued_certificate))
// }

// async fn issuer_from_attributes<'a>(
//     attributes: &Attributes,
//     kms: &KMS,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
// ) -> KResult<Option<Issuer>> {
//     // Retrieve the issuer certificate id if provided
//     let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
//     // Retrieve the issuer private key id if provided
//     let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
//     // Retrieve the issuer certificate and the issuer private key
//     if issuer_certificate_id.is_none() && issuer_private_key_id.is_none() {
//         return Ok(None);
//     }
//     let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
//         issuer_private_key_id.map(|id| id.to_string()),
//         issuer_certificate_id.map(|id| id.to_string()),
//         kms,
//         user,
//         params,
//     )
//     .await?;
//     // convert to openssl
//     let issuer_pkey = kmip_private_key_to_openssl(&issuer_private_key.object)?;
//     let issuer_x509 = kmip_certificate_to_openssl(&issuer_certificate.object)?;
//     Ok(Some(Issuer::from_x509(
//         UniqueIdentifier::TextString(issuer_certificate.id),
//         issuer_pkey,
//         issuer_x509,
//     )))
// }

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

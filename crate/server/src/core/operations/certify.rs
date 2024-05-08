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
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    x509::{X509Name, X509Req, X509},
};
use tracing::trace;
use uuid::Uuid;

use crate::{
    core::{
        certificate::retrieve_issuer_private_key_and_certificate,
        extra_database_params::ExtraDatabaseParams, KMS,
    },
    database::{
        object_with_metadata::ObjectWithMetadata, retrieve_object_for_operation, AtomicOperation,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

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
    }
    create_certificate_from_subject(kms, request, user, params).await
}

async fn create_certificate_from_csr(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let csr_bytes = request.certificate_request_value.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify with CSR: the certificate signing request is missing".to_string(),
        )
    })?;

    // Parse the CSR
    let (certificate_subject_name, certificate_public_key) =
        parse_csr(csr_bytes, &request.certificate_request_type)?;

    // we need these later
    let attributes = request.attributes.cloned().unwrap_or(Default::default());
    let tags = attributes.map(|attrs| attrs.get_tags());

    let (certificate_id, certificate) = certificate_from_subject_and_pk(
        certificate_subject_name,
        certificate_public_key,
        kms,
        request,
        user,
        params,
    )
    .await?;

    // Note: this will overwrite an existing certificate
    kms.db
        .upsert(
            &certificate_id.to_string(),
            user,
            &certificate,
            &attributes,
            tags.as_ref(),
            StateEnumeration::Active,
            params,
        )
        .await?;

    Ok(CertifyResponse {
        unique_identifier: certificate_id,
    })
}

async fn create_certificate_from_public_key(
    mut public_key: ObjectWithMetadata,
    kms: &KMS,
    mut request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let attributes = request.attributes.as_mut().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify with CSR: the attributes specifying the issuer private key is (and/or \
             certificate is) as well as the subject ame are missing"
                .to_string(),
        )
    })?;
    let certificate_subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest("The subject name is not found in the attributes".to_string())
        })?
        .subject_name()?;

    // Convert the Public Key to openssl format
    let certificate_pkey = kmip_public_key_to_openssl(&public_key.object)?;

    // we want to transfer some of the public key attributes to the certificate
    // links to the private key, if any, user tags
    if let Some(link) = public_key.attributes.get_link(LinkType::PrivateKeyLink) {
        attributes.add_link(LinkType::PrivateKeyLink, link)
    }
    // link to this public key
    attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(public_key.id),
    );
    // Merge public key tags and tags passed in the request
    let user_tags: HashSet<String> = public_key
        .attributes
        .get_tags()
        .extend(
            request
                .attributes
                .as_ref()
                .map(|attrs| attrs.get_tags())
                .unwrap_or(HashSet::new()),
        )
        .into_iter()
        .filter(|t| !t.starts_with('_'))
        .collect();
    attributes.set_tags(user_tags)?;

    // generate a certificate and id
    let (certificate_id, certificate) = certificate_from_subject_and_pk(
        certificate_subject_name,
        certificate_pkey,
        kms,
        request,
        user,
        params,
    )
    .await?;

    // Update the public key with the certificate info
    public_key.attributes.add_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(certificate_id.clone()),
    );

    kms.db.atomic(
        user,
        vec![
            // upsert the certificate
            AtomicOperation::Upsert((
                certificate_id,
                certificate,
                attributes.clone(),
                Some(tags),
                StateEnumeration::Active,
            )),
            // update the public key
            AtomicOperation::UpdateObject((
                public_key.id.clone(),
                public_key.object,
                public_key.attributes,
                None,
            )),
        ],
    )
}

async fn create_certificate_from_subject(
    kms: &KMS,
    mut request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let attributes = request.attributes.as_mut().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify with CSR: the attributes specifying the issuer private key is (and/or \
             certificate is) as well as the subject ame are missing"
                .to_string(),
        )
    })?;
    let certificate_subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest("The subject name is not found in the attributes".to_string())
        })?
        .subject_name()?;

    // Convert the Public Key to openssl format
    let certificate_pkey = kmip_public_key_to_openssl(&public_key.object)?;

    // we want to transfer some of the public key attributes to the certificate
    // links to the private key, if any, user tags
    if let Some(link) = public_key.attributes.get_link(LinkType::PrivateKeyLink) {
        attributes.add_link(LinkType::PrivateKeyLink, link)
    }
    // link to this public key
    attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(public_key.id),
    );
    // Merge public key tags and tags passed in the request
    let user_tags: HashSet<String> = public_key
        .attributes
        .get_tags()
        .extend(
            request
                .attributes
                .as_ref()
                .map(|attrs| attrs.get_tags())
                .unwrap_or(HashSet::new()),
        )
        .into_iter()
        .filter(|t| !t.starts_with('_'))
        .collect();
    attributes.set_tags(user_tags)?;

    certificate_from_subject_and_pk(
        certificate_subject_name,
        certificate_pkey,
        kms,
        request,
        user,
        params,
    )
    .await
}

async fn original(request: Certify) -> KResult<CertifyResponse> {
    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);

    // Retrieve the issuer certificate and the issuer private key
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id,
        issuer_certificate_id,
        kms,
        user,
        params,
    )
    .await?;

    // convert to openssl
    let issuer_pkey = kmip_private_key_to_openssl(&issuer_private_key.object)?;
    let issuer_x509 = kmip_certificate_to_openssl(&issuer_certificate.object)?;

    // It is either a CSR or a public key
    let (certificate_id, operations) = if let Some(csr_bytes) = request.certificate_request_value {
        // It is a CSR
        let (certificate_subject_name, certificate_public_key) =
            parse_csr(&csr_bytes, &request.certificate_request_type)?;
        let (issued_certificate_id, issued_certificate) = build_certificate(
            &mut tags,
            &mut attributes,
            &issuer_certificate.id,
            &issuer_pkey,
            &issuer_x509,
            now,
            number_of_days,
            certificate_subject_name,
            certificate_public_key,
        )?;
        (
            issued_certificate_id.clone(),
            vec![
                // upsert the certificate
                AtomicOperation::Upsert((
                    issued_certificate_id,
                    issued_certificate,
                    attributes,
                    Some(tags),
                    StateEnumeration::Active,
                )),
            ],
        )
    } else if let Some(public_key_id) = &request.unique_identifier {
        let public_key_id = public_key_id
            .as_str()
            .context("Certify: public key unique_identifier must be a string")?;
        let mut public_key_owm = retrieve_object_for_operation(
            public_key_id,
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let certificate_public_key = kmip_public_key_to_openssl(&public_key_owm.object)?;
        let certificate_subject_name = attributes
            .certificate_attributes
            .as_ref()
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "The subject name is not found in the attributes".to_string(),
                )
            })?
            .subject_name()?;
        // Add link to the public key in certificate
        attributes.add_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(public_key_id.to_string()),
        );
        let (issued_certificate_id, issued_certificate) = build_certificate(
            &mut tags,
            &mut attributes,
            &issuer_certificate.id,
            &issuer_pkey,
            &issuer_x509,
            now,
            number_of_days,
            certificate_subject_name,
            certificate_public_key,
        )?;
        // Add link to certificate in public key
        public_key_owm.object.attributes_mut()?.add_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(issued_certificate_id.clone()),
        );
        let pk_own_obj_attributes = public_key_owm.object.attributes()?.clone();
        // return
        (
            issued_certificate_id.clone(),
            vec![
                // upsert the certificate
                AtomicOperation::Upsert((
                    issued_certificate_id,
                    issued_certificate,
                    attributes.clone(),
                    Some(tags),
                    StateEnumeration::Active,
                )),
                // update the public key
                AtomicOperation::UpdateObject((
                    public_key_owm.id.clone(),
                    public_key_owm.object,
                    pk_own_obj_attributes,
                    None,
                )),
            ],
        )
    } else {
        kms_bail!(KmsError::InvalidRequest(
            "Either a certificate signing request or a public key must be provided".to_string()
        ))
    };

    // perform DB operations
    kms.db.atomic(user, &operations, params).await?;

    Ok(CertifyResponse {
        unique_identifier: UniqueIdentifier::TextString(certificate_id),
    })
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
    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);
    // Retrieve the issuer certificate and the issuer private key
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id,
        issuer_certificate_id,
        kms,
        user,
        params,
    )
    .await?;
    // convert to openssl
    let issuer_pkey = kmip_private_key_to_openssl(&issuer_private_key.object)?;
    let issuer_x509 = kmip_certificate_to_openssl(&issuer_certificate.object)?;

    // Retrieve and update tags
    let mut tags = attributes.remove_tags().unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }

    // Handle expiration dates
    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;
    // retrieve the number of days for the validity of the certificate
    // the number of days cannot exceed that of the issuer certificate
    let number_of_days = min(
        issuer_x509.not_after().diff(&now)?.days as usize,
        attributes
            .extract_requested_validity_days()?
            .unwrap_or(3650),
    );

    let issued_certificate = build_certificate(
        &mut tags,
        &mut attributes,
        &issuer_certificate.id,
        &issuer_pkey,
        &issuer_x509,
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

#[allow(clippy::too_many_arguments)]
fn build_certificate(
    tags: &mut HashSet<String>,
    attributes: &mut Attributes,
    issuer_certificate_id: &str,
    issuer_pkey: &PKey<Private>,
    issuer_x509: &X509,
    now: Asn1Time,
    number_of_days: usize,
    subject_name: X509Name,
    certificate_public_key: PKey<Public>,
) -> Result<Object, KmsError> {
    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(X509_VERSION3)?;
    x509_builder.set_subject_name(subject_name.as_ref())?;
    x509_builder.set_pubkey(certificate_public_key.as_ref())?;
    x509_builder.set_not_before(now.as_ref())?;
    // Sign the X509 struct with the PKey struct.
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days as u32)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;
    x509_builder.set_issuer_name(issuer_x509.subject_name())?;
    x509_builder.sign(issuer_pkey, MessageDigest::sha256())?;

    // Extensions
    if let Some(extensions) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION)
    {
        let extensions_as_str = String::from_utf8(extensions.to_vec())?;

        let context = x509_builder.x509v3_context(Some(issuer_x509), None);

        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
    }

    let x509 = x509_builder.build();

    // link the certificate to the issuer certificate
    attributes.add_link(
        LinkType::CertificateLink,
        // LinkType::ParentLink,
        LinkedObjectIdentifier::TextString(issuer_certificate_id.to_string()),
    );

    // add the certificate "system" tag
    tags.insert("_cert".to_string());
    let certificate_attributes = CertificateAttributes::from(&x509);
    attributes.certificate_attributes = Some(Box::new(certificate_attributes));

    openssl_certificate_to_kmip(&x509).map_err(KmsError::from)
}

fn parse_csr(
    pkcs10_bytes: &[u8],
    csr_type: &Option<CertificateRequestType>,
) -> KResult<(X509Name, PKey<Public>)> {
    let csr = match csr_type.as_ref().unwrap_or(&CertificateRequestType::PEM) {
        CertificateRequestType::PEM => X509Req::from_pem(pkcs10_bytes),
        CertificateRequestType::PKCS10 => X509Req::from_der(pkcs10_bytes),
        CertificateRequestType::CRMF => kms_bail!(KmsError::InvalidRequest(
            "Certificate Request Type CRMF not supported".to_string()
        )),
    }?;

    let subject_name = csr.subject_name().to_owned()?;
    let public_key = csr.public_key()?.clone();

    Ok((subject_name, public_key))
}

use std::{cmp::min, collections::HashSet};

use cosmian_kmip::{
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::Object,
        kmip_operations::{Certify, CertifyResponse},
        kmip_types::{
            Attributes, CertificateRequestType, LinkType, LinkedObjectIdentifier, StateEnumeration,
            UniqueIdentifier,
        },
    },
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_certificate_to_kmip,
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    x509::{X509Name, X509Req, X509},
};
use tracing::trace;

use crate::{
    core::{
        certificate::{
            add_attributes_to_certificate_tags, add_certificate_system_tags,
            retrieve_matching_private_key_and_certificate,
        },
        extra_database_params::ExtraDatabaseParams,
        KMS,
    },
    database::{retrieve_object_for_operation, AtomicOperation},
    error::KmsError,
    kms_bail,
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

    let mut attributes = request.attributes.clone().ok_or(KmsError::InvalidRequest(
        "Attributes specifying the issuer private key id are missing".to_string(),
    ))?;

    // Retrieve and update tags
    let mut tags = attributes.remove_tags().unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }

    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);

    // Retrieve the issuer certificate and the issuer private key
    let (issuer_private_key, issuer_certificate) = retrieve_matching_private_key_and_certificate(
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
        // return
        (
            issued_certificate_id.clone(),
            vec![
                // upsert the certificate
                AtomicOperation::Upsert((
                    issued_certificate_id,
                    issued_certificate,
                    Some(tags),
                    StateEnumeration::Active,
                )),
                // update the public key
                AtomicOperation::UpdateObject((
                    public_key_owm.id.clone(),
                    public_key_owm.object,
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
) -> Result<(String, Object), KmsError> {
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
        LinkedObjectIdentifier::TextString(issuer_certificate_id.to_string()),
    );

    // add the tags
    add_certificate_system_tags(tags, &x509)?;
    // workaround for #88
    add_attributes_to_certificate_tags(tags, attributes)?;

    let (issued_certificate_id, issued_certificate) = openssl_certificate_to_kmip(x509)?;
    Ok((issued_certificate_id, issued_certificate))
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

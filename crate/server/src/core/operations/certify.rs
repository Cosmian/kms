use std::cmp::min;

use cosmian_kmip::{
    kmip::{
        kmip_operations::{Certify, CertifyResponse},
        kmip_types::{CertificateRequestType, StateEnumeration},
    },
    openssl::{kmip_private_key_to_openssl, openssl_certificate_to_kmip},
    result::KmipResultHelper,
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::certificate::attributes::{
        issuer_private_key_id_from_attributes, number_of_days_from_attributes,
    },
    tagging::{check_user_tags, remove_tags},
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use tracing::trace;

use crate::{
    core::{
        certificate::{add_certificate_system_tags, retrieve_certificate_for_private_key},
        KMS,
    },
    database::retrieve_object_for_operation,
    error::KmsError,
    kms_bail,
    result::KResult,
};

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
    if request.unique_identifier.is_some() {
        kms_bail!(KmsError::NotSupported(
            "Creating a certificate by signing a public key is not supported yet".to_string()
        ))
    }

    let mut attributes = request.attributes.clone().ok_or(KmsError::InvalidRequest(
        "Attributes specifying the issuer private key id are missing".to_string(),
    ))?;

    // Retrieve and update tags
    let mut tags = remove_tags(&mut attributes).unwrap_or_default();
    if !tags.is_empty() {
        check_user_tags(&tags)?;
    }

    // Get the issuer private key
    let issuer_private_key_id =
        issuer_private_key_id_from_attributes(&attributes)?.ok_or_else(|| {
            KmsError::InvalidRequest(
                "The private key of the issuer is not found in the attributes".to_string(),
            )
        })?;
    let issuer_private_key = retrieve_object_for_operation(
        &issuer_private_key_id,
        ObjectOperationType::Certify,
        kms,
        user,
        params,
    )
    .await?;
    // Convert to an openssl PrivateKey
    let issuer_pkey: PKey<Private> = kmip_private_key_to_openssl(&issuer_private_key.object)?;

    //retrieve the certificate associated with the private key
    let (issuer_certificate_owm, issuer_certificate) = retrieve_certificate_for_private_key(
        &issuer_private_key.object,
        ObjectOperationType::Get,
        kms,
        user,
        params,
    )
    .await?;

    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;

    // retrieve the number of days for the validity of the certificate
    // the number of days cannot exceed that of the issuer certificate
    let number_of_days = min(
        issuer_certificate.not_after().diff(&now)?.days as usize,
        number_of_days_from_attributes(&attributes)?.unwrap_or(3650),
    );

    // Parse the CSR
    let csr_bytes = request
        .certificate_request_value
        .context("the certificate request must be provided")?;
    let csr = match request.certificate_request_type {
        Some(CertificateRequestType::PEM) => X509Req::from_pem(&csr_bytes),
        Some(CertificateRequestType::PKCS10) => X509Req::from_der(&csr_bytes),
        Some(CertificateRequestType::CRMF) => kms_bail!(KmsError::InvalidRequest(
            "Certificate Request Type CRMF not supported".to_string()
        )),
        None => kms_bail!(KmsError::InvalidRequest(
            "the certificate Request Type must be provided (PEM or PKCS10)".to_string()
        )),
    }?;

    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(3)?;
    x509_builder.set_subject_name(csr.subject_name())?;
    x509_builder.set_pubkey(csr.public_key()?.as_ref())?;
    x509_builder.set_not_before(now.as_ref())?;
    // Sign the X509 struct with the PKey struct.
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days as u32)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;
    x509_builder.set_issuer_name(issuer_certificate.subject_name())?;
    x509_builder.sign(&issuer_pkey, MessageDigest::sha256())?;
    let x509 = x509_builder.build();

    // add the tags
    add_certificate_system_tags(&mut tags, &x509)?;

    let (issued_certificate_id, issued_certificate) = openssl_certificate_to_kmip(x509)?;

    // Add link to the issuer certificate
    //TODO: attributes not supported until https://github.com/Cosmian/kms/issues/88 is fixed; using tags instead
    let issuer_tag = format!("_cert_issuer={}", issuer_certificate_owm.id);
    tags.insert(issuer_tag);

    // save the generated certificate
    kms.db
        .upsert(
            &issued_certificate_id,
            user,
            &issued_certificate,
            Some(&tags),
            StateEnumeration::Active,
            params,
        )
        .await?;

    Ok(CertifyResponse {
        unique_identifier: issued_certificate_id,
    })
}

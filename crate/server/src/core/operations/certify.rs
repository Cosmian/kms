use std::cmp::{max, min};

use cosmian_kmip::{
    kmip::{
        kmip_operations::{Certify, CertifyResponse},
        kmip_types::CertificateRequestType,
    },
    openssl::openssl_certificate_to_kmip,
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
    pkey::PKey,
    x509::{X509Req, X509},
};
use tracing::trace;

use crate::{
    core::{certificate::retrieve_certificate_for_private_key, KMS},
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
    let tags = remove_tags(&mut attributes);
    if let Some(tags) = &tags {
        check_user_tags(tags)?;
    }

    // Get the issuer private key
    let issuer_private_key_id =
        issuer_private_key_id_from_attributes(&attributes)?.ok_or_else(|| {
            KmsError::InvalidRequest(
                "The private key of the issuer is not found in the attributes".to_string(),
            )
        })?;
    let ca_private_key = retrieve_object_for_operation(
        &issuer_private_key_id,
        ObjectOperationType::Certify,
        kms,
        user,
        params,
    )
    .await?;
    // Expect the bytes to in PKCS#8 format
    let ca_private_key_bytes = ca_private_key.key_block()?.key_bytes()?;
    // Convert to an openssl PrivateKey
    let private_pkey = PKey::private_key_from_pem(&ca_private_key_bytes)?;

    //retrieve the certificate associated with the private key
    let (_issuer_certificate_owm, issuer_certificate) =
        retrieve_certificate_for_private_key(&ca_private_key, kms, false, user, params).await?;

    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;

    // retrieve the number of days for the validity of the certificate
    // the number of days cannot exceed that of the issuer certificate
    let number_of_days = min(
        issuer_certificate.not_after().diff(&now).num_days() as usize,
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
    x509_builder.set_version(2)?;
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
    x509_builder.sign(&private_pkey, openssl::hash::MessageDigest::sha256())?;

    let x509 = x509_builder.build();
    // // Encode the X509 struct to a PEM-encoded certificate.
    // let pem_certificate = x509.to_pem().unwrap();

    Ok(CertifyResponse {
        unique_identifier: "BLAH".to_string(),
    })
}

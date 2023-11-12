use cosmian_kmip::kmip::{
    kmip_operations::{Certify, CertifyResponse},
    kmip_types::CertificateRequestType,
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::certificate::attributes::ca_subject_common_names_from_attributes,
    tagging::{check_user_tags, remove_tags},
};
use openssl::{
    pkey::PKey,
    x509::{X509Req, X509},
};
use tracing::{debug, trace};

use crate::{
    core::{certificate::create_ca_certificate::create_ca_chain, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub async fn sign_certificate_request(
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let mut attributes = request.attributes.clone().ok_or(KmsError::InvalidRequest(
        "Attributes specifying the chain of certification are mandatory".to_string(),
    ))?;

    // Retrieve and update tags
    let tags = remove_tags(&mut attributes);
    if let Some(tags) = &tags {
        check_user_tags(tags)?;
    }

    // Get the full CA chain Subject Common Names separated by slashes.
    // If no CA/SubCA certificate exists, the KMS server will create them.
    // Example:
    // - "CA Root/Sub CA"
    // -> "CA Root" is the Subject Common Name of the root CA
    // -> "Sub CA" is the Subject Common Name of the intermediate CA
    let ca_subject_common_names = ca_subject_common_names_from_attributes(&attributes)?
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "The full chain of CA Subject Common Names are not found in the attributes"
                    .to_string(),
            )
        })?;
    debug!(
        "CA Subject Common Names on input: {:?}",
        &ca_subject_common_names
    );

    // Create the chain: CA and all subCAs (public key + certificate)
    trace!("Create the CA chain is missing: {ca_subject_common_names:?}");
    let last_ca_signing_key = create_ca_chain(
        &ca_subject_common_names,
        &tags.unwrap_or_default(),
        kms,
        user,
        params,
    )
    .await?;

    // Get the private key of the last CA in the chain
    let ca_private_key = retrieve_object_for_operation(
        &last_ca_signing_key.private_key_uid,
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

    // Parse the CSR
    let csr_bytes = request
        .certificate_request_value
        .context("the certificate request value is missing")?;
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
    let mut x509 = X509::builder().unwrap();
    x509.set_version(2)?;
    x509.set_subject_name(csr.subject_name())?;
    x509.set_pubkey(csr.public_key()?.as_ref())?;

    // Sign the X509 struct with the PKey struct.
    x509.sign(&private_pkey, openssl::hash::MessageDigest::sha256())?;

    // // Encode the X509 struct to a PEM-encoded certificate.
    // let pem_certificate = x509.to_pem().unwrap();

    Ok(CertifyResponse {
        unique_identifier: "BLAH".to_string(),
    })
}

use cosmian_kmip::kmip::{
    kmip_operations::{Certify, CertifyResponse},
    kmip_types::{CertificateRequestType, StateEnumeration},
};
use openssl::{
    pkey::{PKey, Public},
    x509::{X509Name, X509Req},
};

use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams,
        operations::certify::certificate_from_subject_and_pk, KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn create_certificate_from_csr(
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
    let attributes = request.attributes.clone();
    let tags = attributes.as_ref().map(|attrs| attrs.get_tags());

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
            &attributes.unwrap_or(Default::default()),
            tags.as_ref(),
            StateEnumeration::Active,
            params,
        )
        .await?;

    Ok(CertifyResponse {
        unique_identifier: certificate_id,
    })
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

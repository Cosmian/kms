use cosmian_kmip::kmip::kmip_operations::{Certify, CertifyResponse};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{
    core::{certificate::create_leaf_certificate::create_certificate, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn certify(
    kms: &KMS,
    request: Certify,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    trace!("Certify: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }
    if request.certificate_request_type.is_some() {
        kms_bail!(KmsError::InvalidRequest(
            "Certificate Request Type not supported".to_string()
        ))
    }
    if request.certificate_request_value.is_some() {
        kms_bail!(KmsError::InvalidRequest(
            "Certificate Request Value not supported".to_string()
        ))
    }
    if request.attributes.is_none() {
        kms_bail!(KmsError::InvalidRequest(
            "No attributes provided".to_string()
        ))
    }

    trace!("Certify arguments OK");

    create_certificate(&request, kms, owner, params).await
}

use cosmian_kmip::kmip::kmip_operations::{Certify, CertifyResponse};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{
    core::{
        certificate::{
            create_leaf_certificate::create_certificate, sign_csr::sign_certificate_request,
        },
        KMS,
    },
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
    if request.certificate_request_value.is_some() {
        // sign the certificate using a full CSR
        sign_certificate_request(kms, request, user, params).await
    } else if request.attributes.is_some() {
        // using just a few params passed in the request attributes
        create_certificate(&request, kms, user, params).await
    } else {
        kms_bail!(KmsError::InvalidRequest(
            "A CSR or parameters in attributes must be provided".to_string()
        ))
    }
}

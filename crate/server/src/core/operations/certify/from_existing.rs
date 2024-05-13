use cosmian_kmip::kmip::kmip_operations::{Certify, CertifyResponse};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    result::KResult,
};

pub async fn renew_certificate(
    mut existing_certificate: ObjectWithMetadata,
    kms: &KMS,
    mut request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    todo!()
}

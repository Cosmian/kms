use cosmian_kmip::kmip::kmip_operations::{Export, ExportResponse};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::export_get, KMS},
    result::KResult,
};

/// Export an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped
/// If the request contains a `KeyWrapType`, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
pub(crate) async fn export(
    kms: &KMS,
    request: Export,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ExportResponse> {
    trace!("Export: {}", serde_json::to_string(&request)?);
    export_get(kms, request, ObjectOperationType::Export, user, params).await
}

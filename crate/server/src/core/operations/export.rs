use cosmian_kmip::kmip::{
    kmip_operations::{Export, ExportResponse},
    KmipOperation,
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::trace;

use crate::{
    core::{operations::export_get, KMS},
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
    params: Option<&ExtraStoreParams>,
) -> KResult<ExportResponse> {
    trace!("Export: {}", serde_json::to_string(&request)?);
    export_get(kms, request, KmipOperation::Export, user, params).await
}

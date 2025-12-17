use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_operations::{Export, ExportResponse},
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, operations::export_get},
    result::KResult,
};

/// Export an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped.
/// If the request contains a `KeyWrapType`, the key will be unwrapped.
/// If both are present, the key will be wrapped.
/// If none are present, the key will be returned as is.
pub(crate) async fn export(kms: &KMS, request: Export, user: &str) -> KResult<ExportResponse> {
    trace!("{request}");
    Box::pin(export_get(kms, request, KmipOperation::Export, user)).await
}

use cosmian_kmip::kmip::{
    kmip_operations::{Get, GetResponse},
    KmipOperation,
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::trace;

use crate::{
    core::{operations::export_get, KMS},
    result::KResult,
};

/// Get an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped.
/// If the request contains a `KeyWrapType`, the key will be unwrapped.
/// If both are present, the key will be wrapped.
/// If none are present, the key will be returned as is.
pub(crate) async fn get(
    kms: &KMS,
    request: Get,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<GetResponse> {
    trace!("Get: {}", serde_json::to_string(&request)?);
    let response = export_get(kms, request, KmipOperation::Get, user, params)
        .await
        .map(Into::into)?;
    Ok(response)
}

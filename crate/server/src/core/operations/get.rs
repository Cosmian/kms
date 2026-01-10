use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_operations::{Get, GetResponse},
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, operations::export_get},
    result::KResult,
};

/// Get an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped.
/// If the request contains a `KeyWrapType`, the key will be unwrapped.
/// If both are present, the key will be wrapped.
/// If none are present, the key will be returned as is.
pub(crate) async fn get(kms: &KMS, request: Get, user: &str) -> KResult<GetResponse> {
    trace!("Get: {}", serde_json::to_string(&request)?);
    // Box::pin :: see https://rust-lang.github.io/rust-clippy/master/index.html#large_futures
    let response = Box::pin(export_get(kms, request, KmipOperation::Get, user))
        .await
        .map(Into::into)?;
    Ok(response)
}

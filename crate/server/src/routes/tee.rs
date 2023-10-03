use std::sync::Arc;

use actix_web::{
    get,
    web::{Data, Json, Query},
    HttpRequest,
};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_utils::tee::QuoteParams;
use tee_attestation::guess_tee;
use tracing::info;

use crate::{database::KMSServer, result::KResult, routes::KmsError};

/// Get the quote of the server running inside a TEE
///
/// This service is only enabled when the server is running inside a TEE (SEV or SGX)
#[get("/tee/attestation_report")]
pub async fn get_attestation_report(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    let params = Query::<QuoteParams>::from_query(req.query_string())?;
    info!("GET /tee/attestation_report {}", kms.get_user(req)?);
    Ok(Json(
        kms.get_attestation_report(
            b64.decode(&params.nonce)
                .map_err(|_| {
                    KmsError::InvalidRequest(
                        "The nonce should be a valid hexadecimal value".to_string(),
                    )
                })?
                .try_into()
                .map_err(|e| {
                    KmsError::InvalidRequest(format!("The nonce should be 32 bytes long: {e:?}"))
                })?,
        )?,
    ))
}

/// Get the public key of the  enclave
///
/// This service is only enabled when the server is running SGX
#[get("/tee/sgx_enclave_public_key")]
pub async fn get_enclave_public_key(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /tee/sgx_enclave_public_key {}", kms.get_user(req)?);
    Ok(Json(kms.get_sgx_enclave_public_key()?))
}

/// Check if the current program is running inside a tee
#[must_use]
pub fn is_running_inside_tee() -> bool {
    guess_tee().is_ok()
}

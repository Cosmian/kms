use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_operations::{RNGRetrieve, RNGRetrieveResponse},
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::trace;
use openssl::rand::rand_bytes;

use crate::{
    core::{KMS, rng::global_rng},
    error::KmsError,
    result::KResult,
};

/// `RNGRetrieve` operation implementation
///
/// Generates cryptographically secure random bytes. If RNG Parameters are
/// provided they are currently accepted but not used to alter generation.
pub(crate) async fn rng_retrieve(
    kms: &KMS,
    request: RNGRetrieve,
    _user: &str,
    _params: Option<Arc<dyn SessionParams>>,
) -> KResult<RNGRetrieveResponse> {
    trace!("RNGRetrieve: {}", serde_json::to_string(&request)?);
    let req_len = request.data_length.max(0) as usize;
    // Enforce sane upper bound; defaults to 64KiB and can be tuned via env
    let max_len: usize = std::env::var("KMS_MAX_RNG_RETRIEVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64 * 1024);
    if req_len > max_len {
        return Err(KmsError::Kmip21Error(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Field,
            format!("Requested RNG length {req_len} exceeds maximum {max_len}"),
        ));
    }
    let mut data = vec![0u8; req_len];
    if req_len > 0 {
        // Prefer HSM RNG when available; fall back to ANSI X9.31 (AES-256) then OpenSSL
        if let Some(hsm) = kms.hsm.as_ref() {
            // Choose slot from env KMS_HSM_RNG_SLOT or use the first available
            let slot = if let Ok(v) = std::env::var("KMS_HSM_RNG_SLOT") {
                v.parse::<usize>().map_err(|e| {
                    KmsError::InvalidRequest(format!("Invalid KMS_HSM_RNG_SLOT value '{v}': {e}"))
                })?
            } else {
                let slots = hsm.get_available_slot_list().await.map_err(|e| {
                    KmsError::InvalidRequest(format!("Failed to get HSM slot list: {e}"))
                })?;
                *slots
                    .first()
                    .ok_or_else(|| KmsError::InvalidRequest("No configured HSM slots".to_owned()))?
            };
            match hsm.generate_random(slot, req_len).await {
                Ok(bytes) => data.copy_from_slice(&bytes),
                Err(e) => {
                    // Fallback to ANSI X9.31 then OpenSSL on HSM RNG error
                    trace!("HSM RNG failed (slot {slot}): {e}; falling back to ANSI X9.31 RNG");
                    let rng = global_rng();
                    if let Ok(mut rng) = rng.try_lock() {
                        if let Err(err) = rng.generate(&mut data) {
                            trace!("ANSI X9.31 RNG failed: {err}; falling back to OpenSSL RNG");
                            rand_bytes(&mut data)?;
                        }
                    } else {
                        rand_bytes(&mut data)?;
                    }
                }
            }
        } else {
            // Try ANSI X9.31 RNG first for compliance
            let rng = global_rng();
            if let Ok(mut rng) = rng.try_lock() {
                if let Err(err) = rng.generate(&mut data) {
                    trace!("ANSI X9.31 RNG failed: {err}; falling back to OpenSSL RNG");
                    rand_bytes(&mut data)?;
                }
            } else {
                rand_bytes(&mut data)?;
            }
        }
    }
    Ok(RNGRetrieveResponse { data })
}

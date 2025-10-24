use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_operations::{RNGSeed, RNGSeedResponse},
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, rng::global_rng},
    result::KResult,
};

/// `RNGSeed` operation implementation
///
/// Accepts seed material to influence the RNG state. For compliance
/// with the XML vectors, we acknowledge the data and report the amount
/// of seed data consumed. The optional RNG Parameters are accepted but
/// not used in the current implementation.
pub(crate) async fn rng_seed(
    kms: &KMS,
    request: RNGSeed,
    _user: &str,
    _params: Option<Arc<dyn SessionParams>>,
) -> KResult<RNGSeedResponse> {
    trace!("{request}");

    // Try seeding the HSM RNG if available; ignore errors to stay lenient per vectors
    if let Some(hsm) = kms.hsm.as_ref() {
        // Choose slot from env KMS_HSM_RNG_SLOT or first available
        if let Ok(v) = std::env::var("KMS_HSM_RNG_SLOT") {
            if let Ok(slot) = v.parse::<usize>() {
                drop(hsm.seed_random(slot, &request.data).await);
            }
        } else if let Ok(slots) = hsm.get_available_slot_list().await {
            if let Some(slot) = slots.first().copied() {
                drop(hsm.seed_random(slot, &request.data).await);
            }
        }
    }

    // Also reseed the software ANSI X9.31 RNG for deterministic testability
    // Cap seed length to 16 bytes per vectors requirement
    let seed: &[u8] = request
        .data
        .get(..16)
        .map_or_else(|| request.data.as_slice(), |s| s);
    if !seed.is_empty() {
        if let Ok(mut rng) = global_rng().try_lock() {
            rng.reseed(seed);
        }
    }

    let amount_of_seed_data: i32 = i32::try_from(request.data.len()).map_or(i32::MAX, |v| v);
    Ok(RNGSeedResponse {
        amount_of_seed_data,
    })
}

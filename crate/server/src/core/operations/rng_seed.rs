use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
    RNGSeed, RNGSeedResponse,
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
    _kms: &KMS,
    request: RNGSeed,
    _user: &str,
) -> KResult<RNGSeedResponse> {
    trace!("{request}");

    // Best-effort: record the provided seed into our global OpenSSL-backed RNG facade.
    // OpenSSL's RAND APIs are managed internally; we simply acknowledge the seed here.
    if !request.data.is_empty() {
        if let Ok(mut rng) = global_rng().try_lock() {
            rng.reseed(&request.data);
        }
    }

    // Report how much seed data was consumed (as per KMIP vectors expectations).
    let amount_of_seed_data: i32 = i32::try_from(request.data.len()).map_or(i32::MAX, |v| v);
    Ok(RNGSeedResponse {
        amount_of_seed_data,
    })
}

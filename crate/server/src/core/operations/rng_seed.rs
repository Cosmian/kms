use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
    RNGSeed, RNGSeedResponse,
};
use cosmian_logger::trace;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// `RNGSeed` operation implementation
///
/// Accepts seed material to influence the RNG state. For compliance
/// with the XML vectors, we acknowledge the data and report the amount
/// of seed data consumed. The optional RNG Parameters are accepted but
/// not used in the current implementation.
pub(crate) async fn rng_seed(
    kms: &KMS,
    request: RNGSeed,
    _user: &UserId,
) -> KResult<RNGSeedResponse> {
    trace!("{request}");

    // Incorporate seed data into the unified KMS RNG.
    // OpenSSL's RAND_add is called via kms.rng.reseed().
    if !request.data.is_empty() {
        kms.rng
            .reseed(&request.data)
            .map_err(|e| KmsError::InvalidRequest(format!("KmsRng reseed failed: {e}")))?;
    }

    // Report how much seed data was consumed (as per KMIP vectors expectations).
    let amount_of_seed_data: i32 = i32::try_from(request.data.len()).unwrap_or(i32::MAX);
    Ok(RNGSeedResponse {
        amount_of_seed_data,
    })
}

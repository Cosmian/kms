use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
    RNGRetrieve, RNGRetrieveResponse,
};
use cosmian_logger::trace;
use openssl::rand::rand_bytes;

use crate::{core::KMS, error::KmsError, result::KResult};

// Conservative upper bound for RNGRetrieve output (bytes)
const MAX_RNG_RETRIEVE: usize = 64 * 1024; // 64 KiB

/// `RNGRetrieve` operation implementation
///
/// Generates cryptographically secure random bytes. If RNG Parameters are
/// provided they are currently accepted but not used to alter generation.
pub(crate) async fn rng_retrieve(
    _kms: &KMS,
    request: RNGRetrieve,
    _user: &str,
) -> KResult<RNGRetrieveResponse> {
    trace!("RNGRetrieve: {}", serde_json::to_string(&request)?);
    let req_len: usize = usize::try_from(request.data_length.max(0))
        .map_err(|e| KmsError::InvalidRequest(format!("Requested RNG length too large: {e}")))?;
    // Enforce sane upper bound without env dependence
    if req_len > MAX_RNG_RETRIEVE {
        return Err(KmsError::Kmip21Error(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Field,
            format!("Requested RNG length {req_len} exceeds maximum {MAX_RNG_RETRIEVE}"),
        ));
    }
    // Early return on zero length
    if req_len == 0 {
        return Ok(RNGRetrieveResponse { data: Vec::new() });
    }

    // Always fill with OpenSSL RAND_bytes directly (simplest behavior)
    let mut data = vec![0_u8; req_len];
    rand_bytes(&mut data)
        .map_err(|e| KmsError::InvalidRequest(format!("RAND_bytes failed: {e}")))?;
    Ok(RNGRetrieveResponse { data })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_operations::RNGRetrieve;

    use crate::{
        config::ServerParams,
        core::{KMS, operations::rng_retrieve},
        error::KmsError,
        result::KResult,
        tests::test_utils::https_clap_config,
    };

    #[tokio::test]
    async fn rng_retrieve_openssl_only_returns_length() -> KResult<()> {
        let clap_config = https_clap_config();
        let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
        // Intentionally no owner reference needed in this unit test.

        let resp0 = rng_retrieve(&kms, RNGRetrieve { data_length: 0 }, "user").await?;
        if !resp0.data.is_empty() {
            return Err(KmsError::InvalidRequest(
                "expected empty RNG data for zero-length request".to_owned(),
            ));
        }

        let resp = rng_retrieve(&kms, RNGRetrieve { data_length: 32 }, "user").await?;
        if resp.data.len() != 32 {
            return Err(KmsError::InvalidRequest(
                "expected RNG to return requested length".to_owned(),
            ));
        }
        Ok(())
    }
}

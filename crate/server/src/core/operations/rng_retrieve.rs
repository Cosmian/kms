use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::kmip_operations::{RNGRetrieve, RNGRetrieveResponse},
};
use cosmian_logger::trace;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

// Conservative upper bound for RNGRetrieve output (bytes)
const MAX_RNG_RETRIEVE: usize = 64 * 1024; // 64 KiB

/// `RNGRetrieve` operation implementation
///
/// Generates cryptographically secure random bytes. If RNG Parameters are
/// provided they are currently accepted but not used to alter generation.
pub(crate) async fn rng_retrieve(
    kms: &KMS,
    request: RNGRetrieve,
    _user: &UserId,
) -> KResult<RNGRetrieveResponse> {
    trace!("RNGRetrieve request");
    let req_len: usize = usize::try_from(request.data_length).map_err(|_e| {
        KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("RNGRetrieve: invalid Data Length {}", request.data_length),
        )
    })?;
    // Enforce sane upper bound without env dependence
    if req_len > MAX_RNG_RETRIEVE {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("Requested RNG length {req_len} exceeds maximum {MAX_RNG_RETRIEVE}"),
        ));
    }
    // Early return on zero length
    if req_len == 0 {
        return Ok(RNGRetrieveResponse { data: Vec::new() });
    }

    // RNGRetrieve output is handed to clients: use the public DRBG, never the private one
    // that generates keys.
    let mut data = vec![0_u8; req_len];
    kms.rng
        .fill_public_bytes(&mut data)
        .map_err(|e| KmsError::CryptographicError(format!("KmsRng failed: {e}")))?;
    Ok(RNGRetrieveResponse { data })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {

    use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_operations::RNGRetrieve;

    use crate::{
        core::operations::rng_retrieve, error::KmsError, middlewares::UserId, result::KResult,
        tests::test_utils::test_kms,
    };

    #[tokio::test]
    async fn rng_retrieve_openssl_only_returns_length() -> KResult<()> {
        let kms = test_kms().await?;
        // Intentionally no owner reference needed in this unit test.

        let resp0 =
            rng_retrieve(&kms, RNGRetrieve { data_length: 0 }, &UserId::from("user")).await?;
        if !resp0.data.is_empty() {
            return Err(KmsError::InvalidRequest(
                "expected empty RNG data for zero-length request".to_owned(),
            ));
        }

        let resp =
            rng_retrieve(&kms, RNGRetrieve { data_length: 32 }, &UserId::from("user")).await?;
        if resp.data.len() != 32 {
            return Err(KmsError::InvalidRequest(
                "expected RNG to return requested length".to_owned(),
            ));
        }

        // A negative Data Length is an invalid field, not an empty success
        let negative =
            rng_retrieve(&kms, RNGRetrieve { data_length: -1 }, &UserId::from("user")).await;
        if !matches!(
            negative,
            Err(KmsError::Kmip21Error(
                cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason::Invalid_Field,
                _
            ))
        ) {
            return Err(KmsError::InvalidRequest(
                "expected Invalid_Field for a negative Data Length".to_owned(),
            ));
        }
        Ok(())
    }
}

use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::{Hash, HashResponse},
    kmip_types::HashingAlgorithm,
};
use cosmian_kms_interfaces::SessionParams;
use openssl::hash::{hash, Hasher, MessageDigest};
use tracing::trace;

use crate::{core::KMS, kms_bail, result::KResult};

pub(crate) async fn hash_operation(
    _kms: &KMS,
    request: Hash,
    _user: &str,
    _params: Option<Arc<dyn SessionParams>>,
) -> KResult<HashResponse> {
    trace!("Hash: {}", serde_json::to_string(&request)?);

    let Some(algorithm) = request.cryptographic_parameters.hashing_algorithm else {
        kms_bail!("Hashing algorithm is required");
    };

    let message_digest = match algorithm {
        HashingAlgorithm::SHA1 => MessageDigest::sha1(),
        HashingAlgorithm::SHA224 => MessageDigest::sha224(),
        HashingAlgorithm::SHA256 => MessageDigest::sha256(),
        HashingAlgorithm::SHA384 => MessageDigest::sha384(),
        HashingAlgorithm::SHA512 => MessageDigest::sha512(),
        HashingAlgorithm::SHA3224 => MessageDigest::sha3_224(),
        HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
        HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
        HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
        algorithm => kms_bail!("Unsupported hashing algorithm: {:?}", algorithm),
    };

    match (request.data, request.correlation_value) {
        (Some(data), Some(correlation_value)) => {
            let mut h = Hasher::new(message_digest)?;
            h.update(&correlation_value)?;
            h.update(&data)?;
            let hashed_data = h.finish()?;
            let response = if request.final_indicator == Some(true) {
                HashResponse {
                    data: Some(hashed_data.to_vec()),
                    correlation_value: None,
                }
            } else {
                HashResponse {
                    data: None,
                    correlation_value: Some(hashed_data.to_vec()),
                }
            };
            Ok(response)
        }
        (Some(data), None) => {
            let hashed_data = hash(message_digest, &data)?;
            let response = if request.init_indicator == Some(true) {
                // Initialize the stream hashing
                HashResponse {
                    data: None,
                    correlation_value: Some(hashed_data.to_vec()),
                }
            } else {
                HashResponse {
                    data: Some(hashed_data.to_vec()),
                    correlation_value: None,
                }
            };
            Ok(response)
        }
        (None, Some(_) | None) => kms_bail!("Data is required"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use cosmian_kmip::kmip_2_1::{
        kmip_operations::Hash,
        kmip_types::{CryptographicParameters, HashingAlgorithm},
    };

    use crate::{
        config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
    };

    #[tokio::test]
    async fn test_server_hash_operation() -> KResult<()> {
        let kms = Arc::new(KMS::instantiate(ServerParams::try_from(https_clap_config())?).await?);

        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let response = kms.hash(request, "test", None).await.unwrap();
        assert_eq!(
            response.data,
            Some(vec![
                253, 23, 128, 166, 252, 158, 224, 218, 178, 108, 235, 75, 57, 65, 171, 3, 230, 108,
                205, 151, 13, 29, 185, 22, 18, 198, 109, 244, 81, 91, 10, 10
            ])
        );
        assert_eq!(response.correlation_value, None);
        Ok(())
    }
}

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::kmip_operations::{Hash, HashResponse},
};
use cosmian_logger::trace;
use openssl::hash::{Hasher, MessageDigest};

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

fn compute_hash(
    data: &[u8],
    algorithm: HashingAlgorithm,
    additional_data: Option<Vec<u8>>,
) -> KResult<Vec<u8>> {
    let message_digest = match algorithm {
        HashingAlgorithm::SHA256 => MessageDigest::sha256(),
        HashingAlgorithm::SHA384 => MessageDigest::sha384(),
        HashingAlgorithm::SHA512 => MessageDigest::sha512(),
        HashingAlgorithm::SHA3224 => MessageDigest::sha3_224(),
        HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
        HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
        HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
        algorithm => kms_bail!("Unsupported hashing algorithm: {:?}", algorithm),
    };

    let mut h = Hasher::new(message_digest)?;
    if let Some(additional_data) = additional_data {
        h.update(&additional_data)?;
    }
    h.update(data)?;

    Ok(h.finish()?.to_vec())
}

pub(crate) async fn hash_operation(
    _kms: &KMS,
    request: Hash,
    _user: &str,
) -> KResult<HashResponse> {
    trace!("Hash: {}", serde_json::to_string(&request)?);

    let algorithm = request
        .cryptographic_parameters
        .hashing_algorithm
        .ok_or_else(|| KmsError::InvalidRequest("Hashing algorithm is required".to_owned()))?;

    let data = request.data.unwrap_or_default();

    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        kms_bail!("Invalid request: init_indicator and final_indicator cannot both be true");
    }

    let hash = compute_hash(&data, algorithm, request.correlation_value)?;

    Ok(HashResponse {
        data: (!request.init_indicator.unwrap_or(false)).then_some(hash.clone()),
        correlation_value: request.init_indicator.unwrap_or(false).then_some(hash),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{kmip_operations::Hash, kmip_types::CryptographicParameters},
    };

    use crate::{
        config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
    };

    #[allow(clippy::unwrap_in_result)]
    #[tokio::test]
    async fn test_server_hash_operation() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
        );

        let expected_hash = vec![
            253, 23, 128, 166, 252, 158, 224, 218, 178, 108, 235, 75, 57, 65, 171, 3, 230, 108,
            205, 151, 13, 29, 185, 22, 18, 198, 109, 244, 81, 91, 10, 10,
        ];

        // Test different combinations of init_indicator and final_indicator
        for (init_indicator, final_indicator) in [
            (None, None),
            (Some(false), None),
            (Some(false), Some(true)),
            (None, Some(true)),
        ] {
            let request = Hash {
                cryptographic_parameters: CryptographicParameters {
                    hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                    ..Default::default()
                },
                data: Some(vec![1, 2, 3]),
                correlation_value: None,
                init_indicator,
                final_indicator,
            };
            let response = kms.hash(request, "test").await.unwrap();
            assert_eq!(response.data, Some(expected_hash.clone()));
            assert_eq!(response.correlation_value, None);
        }

        Ok(())
    }

    #[allow(clippy::unwrap_in_result)]
    #[tokio::test]
    async fn test_server_hash_operation_with_correlation() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
        );

        // Test with correlation value and init indicator
        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: Some(vec![4, 5, 6]),
            init_indicator: Some(true),
            final_indicator: Some(true),
        };
        kms.hash(request, "test").await.unwrap_err();

        // Test different hashing algorithms
        for algorithm in [
            HashingAlgorithm::SHA384,
            HashingAlgorithm::SHA512,
            HashingAlgorithm::SHA3224,
            HashingAlgorithm::SHA3384,
            HashingAlgorithm::SHA3512,
        ] {
            let request = Hash {
                cryptographic_parameters: CryptographicParameters {
                    hashing_algorithm: Some(algorithm),
                    ..Default::default()
                },
                data: Some(vec![1, 2, 3]),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            };
            let response = kms.hash(request, "test").await.unwrap();
            assert!(response.data.is_some());
            assert_eq!(response.correlation_value, None);
        }

        // Test invalid request (missing data)
        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            },
            data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let response = kms.hash(request, "test").await?;
        assert!(response.data.is_some());
        assert!(response.correlation_value.is_none());

        // Test invalid request (missing algorithm)
        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: None,
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        kms.hash(request, "test").await.unwrap_err();

        Ok(())
    }
}

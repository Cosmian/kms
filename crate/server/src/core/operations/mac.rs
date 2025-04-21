use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{
        KmipOperation,
        kmip_operations::{Mac, MacResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_kms_interfaces::SessionParams;
use openssl::{md::Md, md_ctx::MdCtx, pkey::PKey};
use tracing::{debug, trace};

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

fn compute_hmac(key: &[u8], data: &[u8], algorithm: HashingAlgorithm) -> KResult<Vec<u8>> {
    let message_digest = match algorithm {
        HashingAlgorithm::SHA256 => Md::sha256(),
        HashingAlgorithm::SHA384 => Md::sha384(),
        HashingAlgorithm::SHA512 => Md::sha512(),
        HashingAlgorithm::SHA3224 => Md::sha3_224(),
        HashingAlgorithm::SHA3256 => Md::sha3_256(),
        HashingAlgorithm::SHA3384 => Md::sha3_384(),
        HashingAlgorithm::SHA3512 => Md::sha3_512(),
        algorithm => kms_bail!("Unsupported hashing algorithm: {:?}", algorithm),
    };

    let key = PKey::hmac(key)?;
    let mut ctx = MdCtx::new()?;
    ctx.digest_sign_init(Some(message_digest), &key)?;
    ctx.digest_sign_update(data)?;
    let mut hmac = Vec::with_capacity(64); // 512 bits being the maximum size of supported hash functions
    ctx.digest_sign_final_to_vec(&mut hmac)?;
    debug!("HMAC: {:?}", hmac);
    Ok(hmac)
}

pub(crate) async fn mac(
    kms: &KMS,
    request: Mac,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<MacResponse> {
    trace!("Mac: {}", serde_json::to_string(&request)?);

    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Mac: unique_identifier must be a string")?;
    trace!("Mac: Unique identifier: {uid}");

    let algorithm = request
        .cryptographic_parameters
        .hashing_algorithm
        .ok_or_else(|| KmsError::InvalidRequest("Hashing algorithm is required".to_owned()))?;
    trace!("Mac: algorithm: {algorithm:?}");

    let data = request.data.unwrap_or_default();
    trace!("Mac: data: {data:?}");

    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        kms_bail!("Invalid request: init_indicator and final_indicator cannot both be true");
    }

    let digest = if let Some(correlation_value) = request.correlation_value {
        compute_hmac(&correlation_value, &data, algorithm)?
    } else {
        let owm = retrieve_object_for_operation(uid, KmipOperation::Get, kms, user, params).await?;
        let key_bytes = owm.object().key_block()?.key_bytes()?;
        compute_hmac(key_bytes.as_slice(), &data, algorithm)?
    };

    let response = MacResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        data: (!request.init_indicator.unwrap_or(false)).then_some(digest.clone()),
        correlation_value: request.init_indicator.unwrap_or(false).then_some(digest),
    };
    trace!(
        "Mac response
    : {}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS,
            kmip_operations::Mac,
            kmip_types::{CryptographicAlgorithm, CryptographicParameters},
            requests::symmetric_key_create_request,
        },
    };

    use crate::{
        config::ServerParams,
        core::{KMS, operations::mac::compute_hmac},
        result::KResult,
        tests::test_utils::https_clap_config,
    };

    #[test]
    fn test_compute_hmac_limit_cases() -> KResult<()> {
        // Empty key, empty data
        let key = vec![];
        let data = vec![];
        let result = compute_hmac(&key, &data, HashingAlgorithm::SHA256);
        result.unwrap_err();

        // Empty data
        let key = vec![1, 2, 3, 4];
        let data = vec![];
        let hmac = compute_hmac(&key, &data, HashingAlgorithm::SHA256)?;
        assert!(!hmac.is_empty());

        // Empty key
        let key = vec![];
        let data = vec![1, 2, 3];
        let result = compute_hmac(&key, &data, HashingAlgorithm::SHA256);
        result.unwrap_err();

        // Large data (1MB)
        let key = vec![1, 2, 3, 4];
        let data = vec![0_u8; 1024 * 1024];
        let hmac = compute_hmac(&key, &data, HashingAlgorithm::SHA256)?;
        assert_eq!(hmac.len(), 32);

        // Test all supported algorithms
        let algorithms = vec![
            HashingAlgorithm::SHA256,
            HashingAlgorithm::SHA384,
            HashingAlgorithm::SHA512,
            HashingAlgorithm::SHA3224,
            HashingAlgorithm::SHA3256,
            HashingAlgorithm::SHA3384,
            HashingAlgorithm::SHA3512,
        ];

        for algo in algorithms {
            let hmac = compute_hmac(&key, &data, algo)?;
            assert!(!hmac.is_empty());
        }

        // Test unsupported algorithm
        let result = compute_hmac(&key, &data, HashingAlgorithm::MD5);
        result.unwrap_err();

        Ok(())
    }

    #[tokio::test]
    async fn test_server_mac_operation() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::from(ServerParams::try_from(https_clap_config())?)).await?,
        );

        let unique_identifier = Some(
            kms.create(
                symmetric_key_create_request(
                    None,
                    256,
                    CryptographicAlgorithm::SHA3256,
                    EMPTY_TAGS,
                    false,
                    None,
                )?,
                "user",
                None,
                None,
            )
            .await?
            .unique_identifier,
        );

        let request = Mac {
            unique_identifier: unique_identifier.clone(),
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let response = kms.mac(request, "user", None).await?;
        assert_eq!(response.data.unwrap().len(), 32);
        assert_eq!(response.correlation_value, None);

        // Stream initialization
        let request = Mac {
            unique_identifier: unique_identifier.clone(),
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: Some(true),
            final_indicator: None,
        };
        let response = kms.mac(request, "user", None).await?;
        assert_eq!(response.data, None);
        assert_eq!(response.correlation_value.clone().unwrap().len(), 32);

        // Stream finalization
        let request = Mac {
            unique_identifier,
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: response.correlation_value,
            init_indicator: None,
            final_indicator: Some(true),
        };
        let response = kms.mac(request, "user", None).await?;
        assert_eq!(response.data.unwrap().len(), 32);
        assert_eq!(response.correlation_value, None);
        Ok(())
    }
}

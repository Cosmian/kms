use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::{Mac, MacResponse},
    kmip_types::{HashingAlgorithm, UniqueIdentifier},
    KmipOperation,
};
use cosmian_kms_interfaces::SessionParams;
use openssl::{md::Md, md_ctx::MdCtx, pkey::PKey};
use tracing::trace;

use crate::{
    core::{retrieve_object_utils::retrieve_object_for_operation, KMS},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn mac(
    kms: &KMS,
    request: Mac,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<MacResponse> {
    trace!("Mac: {}", serde_json::to_string(&request)?);

    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Mac: unique_identifier must be a string")?;

    let owm = retrieve_object_for_operation(
        unique_identifier,
        KmipOperation::Get,
        kms,
        user,
        params.clone(),
    )
    .await?;

    let unique_identifier = UniqueIdentifier::TextString(unique_identifier.to_owned());

    // Get key bytes
    let key_bytes = owm.object().key_block()?.key_value.raw_bytes()?;

    let Some(algorithm) = request.cryptographic_parameters.hashing_algorithm else {
        kms_bail!("Hashing algorithm is required");
    };

    let message_digest = match algorithm {
        HashingAlgorithm::SHA1 => Md::sha1(),
        HashingAlgorithm::SHA224 => Md::sha224(),
        HashingAlgorithm::SHA256 => Md::sha256(),
        HashingAlgorithm::SHA384 => Md::sha384(),
        HashingAlgorithm::SHA512 => Md::sha512(),
        HashingAlgorithm::SHA3224 => Md::sha3_224(),
        HashingAlgorithm::SHA3256 => Md::sha3_256(),
        HashingAlgorithm::SHA3384 => Md::sha3_384(),
        HashingAlgorithm::SHA3512 => Md::sha3_512(),
        algorithm => kms_bail!("Unsupported hashing algorithm: {:?}", algorithm),
    };

    match (request.data, request.correlation_value) {
        (Some(data), Some(correlation_value)) => {
            // Create a PKey
            let key = PKey::hmac(&correlation_value)?;
            let mut ctx = MdCtx::new()?;
            // Key has already been hashed
            ctx.digest_sign_init(Some(message_digest), &key)?;
            ctx.digest_sign_update(&data)?;
            let mut hmac = vec![];
            ctx.digest_sign_final_to_vec(&mut hmac)?;

            let response = if request.final_indicator == Some(true) {
                MacResponse {
                    unique_identifier,
                    data: Some(hmac),
                    correlation_value: None,
                }
            } else {
                MacResponse {
                    unique_identifier,
                    data: None,
                    correlation_value: Some(hmac),
                }
            };
            Ok(response)
        }
        (Some(data), None) => {
            // Create a PKey
            let key = PKey::hmac(key_bytes)?;
            // Compute the HMAC.
            let mut ctx = MdCtx::new()?;
            ctx.digest_sign_init(Some(message_digest), &key)?;
            ctx.digest_sign_update(&data)?;
            let mut hmac = vec![];
            ctx.digest_sign_final_to_vec(&mut hmac)?;

            let response = if request.init_indicator == Some(true) {
                // Initialize the stream hashing
                MacResponse {
                    unique_identifier,
                    data: None,
                    correlation_value: Some(hmac),
                }
            } else {
                MacResponse {
                    unique_identifier,
                    data: Some(hmac),
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
        extra::tagging::EMPTY_TAGS,
        kmip_operations::Mac,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm},
        requests::symmetric_key_create_request,
    };

    use crate::{
        config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
    };

    #[tokio::test]
    async fn test_server_mac_operation() -> KResult<()> {
        let kms = Arc::new(KMS::instantiate(ServerParams::try_from(https_clap_config())?).await?);

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

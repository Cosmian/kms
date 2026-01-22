use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{
        KmipOperation,
        kmip_operations::{MAC, MACResponse, MACVerify, MACVerifyResponse},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier, ValidityIndicator},
    },
};
use cosmian_logger::{debug, trace};
use openssl::{md::Md, md_ctx::MdCtx, pkey::PKey};

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

pub(crate) async fn mac(kms: &KMS, request: MAC, user: &str) -> KResult<MACResponse> {
    trace!("Mac: {}", serde_json::to_string(&request)?);

    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Mac: unique_identifier must be a string")?;
    trace!("Mac: Unique identifier: {uid}");

    // Determine hashing algorithm: if explicit cryptographic_parameters supplied use them,
    // otherwise attempt inference from the key's registered CryptographicAlgorithm or its
    // attributes. This aligns with mandatory profile vectors (e.g. CS-AC-M-4-21) that omit
    // explicit cryptographic parameters while expecting a successful MAC computation.
    let algorithm = if let Some(cp) = request.cryptographic_parameters {
        cp.hashing_algorithm
            .ok_or_else(|| KmsError::InvalidRequest("Hashing algorithm is required".to_owned()))?
    } else {
        // Retrieve key now (needed for inference)
        let owm = Box::pin(retrieve_object_for_operation(
            uid,
            KmipOperation::Get,
            kms,
            user,
        ))
        .await?;
        let key_block = owm.object().key_block()?;
        if let Some(ca) = key_block.cryptographic_algorithm {
            match ca {
                CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                CryptographicAlgorithm::HMACSHA3224 => HashingAlgorithm::SHA3224,
                CryptographicAlgorithm::HMACSHA3256 => HashingAlgorithm::SHA3256,
                CryptographicAlgorithm::HMACSHA3384 => HashingAlgorithm::SHA3384,
                CryptographicAlgorithm::HMACSHA3512 => HashingAlgorithm::SHA3512,
                // Non-HMAC algorithms (e.g., AES) cannot directly infer hashing algorithm; try attributes
                _ => {
                    let attrs = owm.attributes();
                    if let Some(cp) = &attrs.cryptographic_parameters {
                        if let Some(ca2) = cp.cryptographic_algorithm {
                            match ca2 {
                                CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                                CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                                CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                                CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                                CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                                CryptographicAlgorithm::HMACSHA3224 => HashingAlgorithm::SHA3224,
                                CryptographicAlgorithm::HMACSHA3256 => HashingAlgorithm::SHA3256,
                                CryptographicAlgorithm::HMACSHA3384 => HashingAlgorithm::SHA3384,
                                CryptographicAlgorithm::HMACSHA3512 => HashingAlgorithm::SHA3512,
                                other => kms_bail!(
                                    "Unsupported HMAC algorithm for MAC inference: {other:?}"
                                ),
                            }
                        } else {
                            kms_bail!(
                                "Missing cryptographic algorithm for MAC inference (attributes cryptographic parameters present without algorithm)"
                            )
                        }
                    } else {
                        kms_bail!(
                            "Cryptographic parameters are required or inferable from key's cryptographic algorithm or attributes"
                        )
                    }
                }
            }
        } else {
            // No algorithm on key_block: fallback to attributes cryptographic_parameters
            let attrs = owm.attributes();
            if let Some(cp) = &attrs.cryptographic_parameters {
                if let Some(ca) = cp.cryptographic_algorithm {
                    match ca {
                        CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                        CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                        CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                        CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                        CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                        CryptographicAlgorithm::HMACSHA3224 => HashingAlgorithm::SHA3224,
                        CryptographicAlgorithm::HMACSHA3256 => HashingAlgorithm::SHA3256,
                        CryptographicAlgorithm::HMACSHA3384 => HashingAlgorithm::SHA3384,
                        CryptographicAlgorithm::HMACSHA3512 => HashingAlgorithm::SHA3512,
                        other => {
                            kms_bail!("Unsupported HMAC algorithm for MAC inference: {other:?}")
                        }
                    }
                } else {
                    kms_bail!(
                        "Missing cryptographic algorithm for MAC inference (attributes cryptographic parameters present without algorithm)"
                    )
                }
            } else {
                kms_bail!(
                    "Cryptographic parameters are required or inferable from key's cryptographic algorithm or attributes"
                )
            }
        }
    };
    trace!("Mac: algorithm: {algorithm:?}");

    let data = request.data.unwrap_or_default();
    trace!("Mac: data: {data:?}");

    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        kms_bail!("Invalid request: init_indicator and final_indicator cannot both be true");
    }

    let digest = if let Some(correlation_value) = request.correlation_value {
        compute_hmac(&correlation_value, &data, algorithm)?
    } else {
        // We may already have retrieved object above for inference; retrieve again (cheap) to simplify code.
        let owm = Box::pin(retrieve_object_for_operation(
            uid,
            KmipOperation::Get,
            kms,
            user,
        ))
        .await?;
        let key_bytes = owm.object().key_block()?.key_bytes().context("mac")?;
        compute_hmac(key_bytes.as_slice(), &data, algorithm)?
    };

    let response = MACResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        mac_data: (!request.init_indicator.unwrap_or(false)).then_some(digest.clone()),
        correlation_value: request.init_indicator.unwrap_or(false).then_some(digest),
    };
    trace!("Mac response: {response}");
    Ok(response)
}

pub(super) async fn mac_verify(
    kms: &KMS,
    request: MACVerify,
    user: &str,
) -> KResult<MACVerifyResponse> {
    trace!("MacVerify: {}", serde_json::to_string(&request)?);
    let UniqueIdentifier::TextString(uid) = &request.unique_identifier else {
        kms_bail!("MacVerify: unique_identifier must be a string")
    };
    trace!("MacVerify: Unique identifier: {uid}");

    // Retrieve key
    let owm = Box::pin(retrieve_object_for_operation(
        uid,
        KmipOperation::Get,
        kms,
        user,
    ))
    .await?;
    let key_block = owm.object().key_block()?;
    let key_bytes = key_block.key_bytes().context("mac_verify")?;

    // Determine hashing algorithm: prefer explicit request param; otherwise infer from key cryptographic algorithm
    let algorithm = if let Some(cp) = request.cryptographic_parameters {
        if let Some(hash) = cp.hashing_algorithm {
            hash
        } else {
            kms_bail!("Hashing algorithm is required in cryptographic parameters if provided")
        }
    } else {
        // Primary inference from key_block's cryptographic_algorithm if it's an HMAC variant
        if let Some(alg) = key_block.cryptographic_algorithm {
            match alg {
                CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                other_alg => {
                    // Fallback: look into attributes cryptographic_parameters
                    let attrs = owm.attributes();
                    if let Some(cp) = &attrs.cryptographic_parameters {
                        if let Some(ca) = cp.cryptographic_algorithm {
                            match ca {
                                CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                                CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                                CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                                CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                                CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                                other => kms_bail!(
                                    "Unsupported HMAC algorithm for inference: {other:?} (key block alg: {other_alg:?})"
                                ),
                            }
                        } else {
                            kms_bail!("Unsupported HMAC algorithm for inference: {other_alg:?}")
                        }
                    } else {
                        kms_bail!("Unsupported HMAC algorithm for inference: {other_alg:?}")
                    }
                }
            }
        } else {
            // No algorithm on key_block: try attributes cryptographic_parameters
            let attrs = owm.attributes();
            if let Some(cp) = &attrs.cryptographic_parameters {
                if let Some(ca) = cp.cryptographic_algorithm {
                    match ca {
                        CryptographicAlgorithm::HMACSHA1 => HashingAlgorithm::SHA1,
                        CryptographicAlgorithm::HMACSHA224 => HashingAlgorithm::SHA224,
                        CryptographicAlgorithm::HMACSHA256 => HashingAlgorithm::SHA256,
                        CryptographicAlgorithm::HMACSHA384 => HashingAlgorithm::SHA384,
                        CryptographicAlgorithm::HMACSHA512 => HashingAlgorithm::SHA512,
                        other => kms_bail!("Unsupported HMAC algorithm for inference: {other:?}"),
                    }
                } else {
                    kms_bail!(
                        "Missing cryptographic algorithm for MACVerify inference (attributes cryptographic parameters present without algorithm)"
                    )
                }
            } else {
                kms_bail!("Missing cryptographic algorithm on key for MACVerify inference")
            }
        }
    };

    // Re-compute algorithm if previous branch attempted unreachable placeholder usage.
    let expected_mac = compute_hmac(key_bytes.as_slice(), &request.data, algorithm)?;
    let validity = if expected_mac == request.mac_data {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    };
    let response = MACVerifyResponse {
        unique_identifier: request.unique_identifier,
        validity_indicator: validity,
    };
    let uid_str = match &response.unique_identifier {
        UniqueIdentifier::TextString(s) => s.as_str(),
        _ => "<non-text-uid>",
    };
    trace!(
        "MacVerify response: uid={}, validity={:?}",
        uid_str, response.validity_indicator
    );
    Ok(response)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS,
            kmip_operations::MAC,
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

    #[allow(clippy::unwrap_in_result)]
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
            )
            .await?
            .unique_identifier,
        );

        let request = MAC {
            unique_identifier: unique_identifier.clone(),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let response = kms.mac(request, "user").await?;
        assert_eq!(response.mac_data.unwrap().len(), 32);
        assert_eq!(response.correlation_value, None);

        // Stream initialization
        let request = MAC {
            unique_identifier: unique_identifier.clone(),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: Some(true),
            final_indicator: None,
        };
        let response = kms.mac(request, "user").await?;
        assert_eq!(response.mac_data, None);
        assert_eq!(response.correlation_value.clone().unwrap().len(), 32);

        // Stream finalization
        let request = MAC {
            unique_identifier,
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: Some(vec![1, 2, 3]),
            correlation_value: response.correlation_value,
            init_indicator: None,
            final_indicator: Some(true),
        };
        let response = kms.mac(request, "user").await?;
        assert_eq!(response.mac_data.unwrap().len(), 32);
        assert_eq!(response.correlation_value, None);
        Ok(())
    }
}

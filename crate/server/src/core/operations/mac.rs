use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::KeyBlock,
            kmip_objects::Object,
            kmip_operations::{MAC, MACResponse, MACVerify, MACVerifyResponse},
            kmip_types::{CryptographicAlgorithm, UniqueIdentifier, ValidityIndicator},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;
use openssl::{md::Md, md_ctx::MdCtx, pkey::PKey};

use crate::{
    core::{
        KMS,
        operations::{
            CryptoOpSpec, ResolvedKey,
            algorithm_policy::enforce_kmip_algorithm_policy_for_retrieved_key,
            resolve_key_for_operation,
        },
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Marker type for the MAC operation's key selection requirements.
pub(crate) struct MacOp;

impl CryptoOpSpec for MacOp {
    const KMIP_OP: KmipOperation = KmipOperation::MAC;
    const OP_NAME: &'static str = "MAC";
    const SUPPORTS_ORACLE: bool = false;

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        // MAC does NOT enforce CryptographicUsageMask::MACGenerate for backward compat.
        matches!(owm.object(), Object::SymmetricKey { .. })
    }

    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        _user: &str,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) | KmsError::Unauthorized(_) => KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("MAC: no valid key for id: {unique_identifier}"),
            ),
            other => other,
        }
    }
}

/// Marker type for the `MACVerify` operation's key selection requirements.
pub(crate) struct MacVerifyOp;

impl CryptoOpSpec for MacVerifyOp {
    const KMIP_OP: KmipOperation = KmipOperation::MAC;
    const OP_NAME: &'static str = "MACVerify";
    const SUPPORTS_ORACLE: bool = false;

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        matches!(owm.object(), Object::SymmetricKey { .. })
    }

    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        _user: &str,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) | KmsError::Unauthorized(_) => KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("MACVerify: no valid key for id: {unique_identifier}"),
            ),
            other => other,
        }
    }
}

fn compute_hmac(key: &[u8], data: &[u8], algorithm: HashingAlgorithm) -> KResult<Vec<u8>> {
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

    let key = PKey::hmac(key)?;
    let mut ctx = MdCtx::new()?;
    ctx.digest_sign_init(Some(message_digest), &key)?;
    ctx.digest_sign_update(data)?;
    let mut hmac = Vec::with_capacity(64); // 512 bits being the maximum size of supported hash functions
    ctx.digest_sign_final_to_vec(&mut hmac)?;
    trace!("HMAC computed: {} bytes", hmac.len());
    Ok(hmac)
}

/// Map a `CryptographicAlgorithm` HMAC variant to its `HashingAlgorithm`.
fn hmac_algorithm_to_hashing(ca: CryptographicAlgorithm) -> KResult<HashingAlgorithm> {
    match ca {
        CryptographicAlgorithm::HMACSHA1 => Ok(HashingAlgorithm::SHA1),
        CryptographicAlgorithm::HMACSHA224 => Ok(HashingAlgorithm::SHA224),
        CryptographicAlgorithm::HMACSHA256 => Ok(HashingAlgorithm::SHA256),
        CryptographicAlgorithm::HMACSHA384 => Ok(HashingAlgorithm::SHA384),
        CryptographicAlgorithm::HMACSHA512 => Ok(HashingAlgorithm::SHA512),
        CryptographicAlgorithm::HMACSHA3224 => Ok(HashingAlgorithm::SHA3224),
        CryptographicAlgorithm::HMACSHA3256 => Ok(HashingAlgorithm::SHA3256),
        CryptographicAlgorithm::HMACSHA3384 => Ok(HashingAlgorithm::SHA3384),
        CryptographicAlgorithm::HMACSHA3512 => Ok(HashingAlgorithm::SHA3512),
        other => Err(KmsError::InvalidRequest(format!(
            "Unsupported HMAC algorithm for inference: {other:?}"
        ))),
    }
}

/// Infer the `HashingAlgorithm` from the key's `KeyBlock` or `Attributes`.
///
/// Tries (in order):
/// 1. `key_block.cryptographic_algorithm` (HMAC variant → direct mapping)
/// 2. `attrs.cryptographic_parameters.cryptographic_algorithm` (fallback)
fn infer_hmac_hashing_algorithm(
    key_block: &KeyBlock,
    attrs: &Attributes,
) -> KResult<HashingAlgorithm> {
    // Try key_block algorithm first
    if let Some(ca) = key_block.cryptographic_algorithm {
        if let Ok(ha) = hmac_algorithm_to_hashing(ca) {
            return Ok(ha);
        }
        // Non-HMAC algorithm on key_block: fall through to attributes
    }
    // Fallback to attributes cryptographic_parameters
    let cp = attrs
        .cryptographic_parameters
        .as_ref()
        .ok_or_else(|| KmsError::InvalidRequest(
            "Cryptographic parameters are required or inferable from key's cryptographic algorithm or attributes".to_owned(),
        ))?;
    let ca = cp.cryptographic_algorithm.ok_or_else(|| {
        KmsError::InvalidRequest(
            "Missing cryptographic algorithm for MAC inference (attributes cryptographic \
             parameters present without algorithm)"
                .to_owned(),
        )
    })?;
    hmac_algorithm_to_hashing(ca)
}

pub(crate) async fn mac(kms: &KMS, request: MAC, user: &str) -> KResult<MACResponse> {
    trace!("uid={:?}", request.unique_identifier);

    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    let mut owm = match resolve_key_for_operation::<MacOp>(unique_identifier, kms, user).await? {
        ResolvedKey::Local(owm) => *owm,
        ResolvedKey::Oracle { .. } => {
            return Err(KmsError::NotSupported(
                "MAC: oracle keys not supported".to_owned(),
            ));
        }
    };

    // Second-stage enforcement: validate the retrieved key's stored attributes.
    enforce_kmip_algorithm_policy_for_retrieved_key(&kms.params, "MAC", owm.id(), &owm)?;

    // Determine hashing algorithm: if explicit cryptographic_parameters supplied use them,
    // otherwise infer from the key's registered CryptographicAlgorithm or its attributes.
    let algorithm = if let Some(cp) = request.cryptographic_parameters {
        cp.hashing_algorithm
            .ok_or_else(|| KmsError::InvalidRequest("Hashing algorithm is required".to_owned()))?
    } else {
        let key_block = owm.object().key_block()?;
        infer_hmac_hashing_algorithm(key_block, owm.attributes())?
    };
    trace!("Mac: algorithm: {algorithm:?}");

    let data = request.data.unwrap_or_default();
    let data_len = data.len();
    trace!("Mac: data: {data:?}");

    // Enforce UsageLimits before the operation.
    super::enforce_usage_limits(&owm, data_len)?;

    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        kms_bail!("Invalid request: init_indicator and final_indicator cannot both be true");
    }

    let digest = if let Some(correlation_value) = request.correlation_value {
        compute_hmac(&correlation_value, &data, algorithm)?
    } else {
        let key_bytes = owm.object().key_block()?.key_bytes().context("mac")?;
        compute_hmac(key_bytes.as_slice(), &data, algorithm)?
    };

    // Post-operation: decrement and persist usage limits.
    super::decrement_usage_limits(kms, &mut owm, "MAC", data_len).await?;

    let response = MACResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        mac_data: (!request.init_indicator.unwrap_or(false)).then_some(digest.clone()),
        correlation_value: request.init_indicator.unwrap_or(false).then_some(digest),
    };
    trace!("Mac response: {response}");
    Ok(response)
}

pub(crate) async fn mac_verify(
    kms: &KMS,
    request: MACVerify,
    user: &str,
) -> KResult<MACVerifyResponse> {
    trace!("uid={}", request.unique_identifier);

    let unique_identifier = &request.unique_identifier;

    let mut owm =
        match resolve_key_for_operation::<MacVerifyOp>(unique_identifier, kms, user).await? {
            ResolvedKey::Local(owm) => *owm,
            ResolvedKey::Oracle { .. } => {
                return Err(KmsError::NotSupported(
                    "MACVerify: oracle keys not supported".to_owned(),
                ));
            }
        };

    // Second-stage enforcement: validate the retrieved key's stored attributes.
    enforce_kmip_algorithm_policy_for_retrieved_key(&kms.params, "MACVerify", owm.id(), &owm)?;

    let data_len = request.data.len();

    // Enforce UsageLimits before the operation.
    super::enforce_usage_limits(&owm, data_len)?;

    let key_block = owm.object().key_block()?;
    let key_bytes = key_block.key_bytes().context("mac_verify")?;

    // Determine hashing algorithm: prefer explicit request param; otherwise infer from key.
    let algorithm = if let Some(cp) = request.cryptographic_parameters {
        cp.hashing_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "Hashing algorithm is required in cryptographic parameters if provided".to_owned(),
            )
        })?
    } else {
        infer_hmac_hashing_algorithm(key_block, owm.attributes())?
    };

    let expected_mac = compute_hmac(key_bytes.as_slice(), &request.data, algorithm)?;
    let validity = if expected_mac == request.mac_data {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    };

    // Post-operation: decrement and persist usage limits.
    super::decrement_usage_limits(kms, &mut owm, "MACVerify", data_len).await?;

    let response = MACVerifyResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        validity_indicator: validity,
    };
    trace!(
        "MacVerify response: uid={}, validity={:?}",
        owm.id(),
        response.validity_indicator
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
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
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
                    VENDOR_ID_COSMIAN,
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

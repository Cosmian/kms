use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, HashingAlgorithm, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::KeyBlock,
            kmip_objects::Object,
            kmip_operations::{MAC, MACResponse, MACVerify, MACVerifyResponse},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier,
                ValidityIndicator,
            },
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;
use openssl::{
    md::{Md, MdRef},
    md_ctx::MdCtx,
    pkey::PKey,
};

use crate::{
    core::{
        KMS,
        operations::{
            CryptoOpSpec, KeysetMode,
            key_ops::multi_part::{Part, StreamOwner, reject_multi_part_for_oracle},
        },
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Marker type for the MAC operation's key selection requirements.
pub(crate) struct MacOp;

impl CryptoOpSpec for MacOp {
    type Request = MAC;
    type Response = MACResponse;

    const KMIP_OP: KmipOperation = KmipOperation::MAC;
    const OP_NAME: &'static str = "MAC";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        request.unique_identifier.as_ref()
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request.data.as_ref().map_or(0, Vec::len)
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        // KMIP 2.1 §4.1: an Active object SHALL only be used for the purposes allowed by its
        // Cryptographic Usage Mask (a key without any mask is accepted).
        matches!(owm.object(), Object::SymmetricKey { .. })
            && owm.has_usage_mask(CryptographicUsageMask::MACGenerate, true)
    }

    fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        user: &UserId,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        let data = part_data(request.data.as_deref(), part, "MAC")?;
        trace!("Mac: part: {part:?}, data len: {}", data.len());
        let owner = StreamOwner {
            op: Self::OP_NAME,
            user,
            key_uid: owm.id(),
        };
        let (mac_data, correlation_value) = kms.multi_part.run(
            &kms.rng,
            part,
            owner,
            || hmac_context(owm, request.cryptographic_parameters.as_ref(), "mac"),
            |ctx, last| {
                ctx.digest_sign_update(data)?;
                Ok(if last { Some(hmac_final(ctx)?) } else { None })
            },
        )?;

        Ok(MACResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            mac_data,
            correlation_value,
        })
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        reject_multi_part_for_oracle(Self::OP_NAME, part)?;
        let data = part_data(request.data.as_deref(), part, "MAC")?;
        let lock = kms.crypto_oracles.read().await;
        let crypto_oracle = lock.get(prefix).ok_or_else(|| {
            KmsError::InvalidRequest(format!("MAC: unknown crypto oracle prefix: {prefix}"))
        })?;
        let mac_data = crypto_oracle
            .mac(uid, data, request.cryptographic_parameters.as_ref())
            .await?;
        Ok(MACResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            mac_data: Some(mac_data),
            correlation_value: None,
        })
    }
}

/// State of a multi-part MAC Verify: the running HMAC and the MAC to check, which may be
/// supplied on the initial or the final part.
struct MacVerifyState {
    ctx: MdCtx,
    mac_data: Vec<u8>,
}

/// Marker type for the `MACVerify` operation's key selection requirements.
pub(crate) struct MacVerifyOp;

impl CryptoOpSpec for MacVerifyOp {
    type Request = MACVerify;
    type Response = MACVerifyResponse;

    const KMIP_OP: KmipOperation = KmipOperation::MAC;
    const OP_NAME: &'static str = "MACVerify";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        Some(&request.unique_identifier)
    }

    fn keyset_mode() -> KeysetMode {
        KeysetMode::TryEach
    }

    /// `MACVerify` accepts Active, Deactivated, and Compromised keys per KMIP 2.1 §3.31.
    fn accepted_states() -> &'static [State] {
        &[State::Active, State::Deactivated, State::Compromised]
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request.data.len()
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        matches!(owm.object(), Object::SymmetricKey { .. })
            && owm.has_usage_mask(CryptographicUsageMask::MACVerify, true)
    }

    fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        user: &UserId,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        if part == Part::Single && request.mac_data.is_empty() {
            return Err(missing_mac_data());
        }
        let owner = StreamOwner {
            op: Self::OP_NAME,
            user,
            key_uid: owm.id(),
        };
        let (validity_indicator, correlation_value) = kms.multi_part.run(
            &kms.rng,
            part,
            owner,
            || {
                Ok(MacVerifyState {
                    ctx: hmac_context(
                        owm,
                        request.cryptographic_parameters.as_ref(),
                        "mac_verify",
                    )?,
                    mac_data: Vec::new(),
                })
            },
            |state, last| {
                state.ctx.digest_sign_update(&request.data)?;
                if !request.mac_data.is_empty() {
                    state.mac_data.clone_from(&request.mac_data);
                }
                if !last {
                    return Ok(None);
                }
                if state.mac_data.is_empty() {
                    return Err(missing_mac_data());
                }
                let computed = hmac_final(&mut state.ctx)?;
                Ok(Some(validity(&computed, &state.mac_data)))
            },
        )?;

        Ok(MACVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            validity_indicator,
            correlation_value,
        })
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        reject_multi_part_for_oracle(Self::OP_NAME, part)?;
        if request.mac_data.is_empty() {
            return Err(missing_mac_data());
        }
        let lock = kms.crypto_oracles.read().await;
        let crypto_oracle = lock.get(prefix).ok_or_else(|| {
            KmsError::InvalidRequest(format!("MACVerify: unknown crypto oracle prefix: {prefix}"))
        })?;
        let valid = crypto_oracle
            .mac_verify(
                uid,
                &request.data,
                &request.mac_data,
                request.cryptographic_parameters.as_ref(),
            )
            .await?;
        Ok(MACVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            validity_indicator: Some(if valid {
                ValidityIndicator::Valid
            } else {
                ValidityIndicator::Invalid
            }),
            correlation_value: None,
        })
    }
}

pub(crate) async fn mac(kms: &KMS, request: MAC, user: &UserId) -> KResult<MACResponse> {
    trace!("uid={:?}", request.unique_identifier);
    Box::pin(kms.perform_crypto_operation::<MacOp>(request, user)).await
}

pub(crate) async fn mac_verify(
    kms: &KMS,
    request: MACVerify,
    user: &UserId,
) -> KResult<MACVerifyResponse> {
    trace!("uid={}", request.unique_identifier);
    Box::pin(kms.perform_crypto_operation::<MacVerifyOp>(request, user)).await
}

// ─── Helper functions ────────────────────────────────────────────────────────

/// Data of a part: required for single-part requests (KMIP 2.1 §6.1), optional otherwise.
fn part_data<'a>(data: Option<&'a [u8]>, part: Part<'_>, op: &str) -> KResult<&'a [u8]> {
    match (data, part) {
        (Some(data), _) => Ok(data),
        (None, Part::Single) => Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("{op}: Data is required for a single-part operation"),
        )),
        (None, _) => Ok(&[]),
    }
}

fn missing_mac_data() -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Invalid_Field,
        "MACVerify: MAC Data is required for a single-part operation or by the final part"
            .to_owned(),
    )
}

/// Constant-time MAC comparison.
fn validity(computed: &[u8], expected: &[u8]) -> ValidityIndicator {
    if computed.len() == expected.len() && openssl::memcmp::eq(computed, expected) {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    }
}

fn hmac_md(algorithm: HashingAlgorithm) -> KResult<&'static MdRef> {
    Ok(match algorithm {
        HashingAlgorithm::SHA1 => Md::sha1(),
        HashingAlgorithm::SHA224 => Md::sha224(),
        HashingAlgorithm::SHA256 => Md::sha256(),
        HashingAlgorithm::SHA384 => Md::sha384(),
        HashingAlgorithm::SHA512 => Md::sha512(),
        HashingAlgorithm::SHA3224 => Md::sha3_224(),
        HashingAlgorithm::SHA3256 => Md::sha3_256(),
        HashingAlgorithm::SHA3384 => Md::sha3_384(),
        HashingAlgorithm::SHA3512 => Md::sha3_512(),
        algorithm => {
            kms_bail!(KmsError::NotSupported(format!(
                "Unsupported hashing algorithm: {algorithm:?}"
            )))
        }
    })
}

/// Start an HMAC with the key of `owm` and the algorithm from the request or the key.
fn hmac_context(
    owm: &ObjectWithMetadata,
    request_parameters: Option<&CryptographicParameters>,
    context: &'static str,
) -> KResult<MdCtx> {
    let key_block = owm.object().key_block()?;
    let algorithm = mac_hashing_algorithm(key_block, owm.attributes(), request_parameters)?;
    trace!("Mac: algorithm: {algorithm:?}");
    hmac_init(key_block.key_bytes_ref().context(context)?, algorithm)
}

fn hmac_init(key: &[u8], algorithm: HashingAlgorithm) -> KResult<MdCtx> {
    let message_digest = hmac_md(algorithm)?;
    let key = PKey::hmac(key)?;
    let mut ctx = MdCtx::new()?;
    // The context keeps its own reference to the key.
    ctx.digest_sign_init(Some(message_digest), &key)?;
    Ok(ctx)
}

fn hmac_final(ctx: &mut MdCtx) -> KResult<Vec<u8>> {
    let mut hmac = Vec::with_capacity(64);
    ctx.digest_sign_final_to_vec(&mut hmac)?;
    trace!("HMAC computed: {} bytes", hmac.len());
    Ok(hmac)
}

/// One-shot HMAC of `data` under `key` (also used by the Derive Key HMAC method).
pub(crate) fn compute_hmac(
    key: &[u8],
    data: &[u8],
    algorithm: HashingAlgorithm,
) -> KResult<Vec<u8>> {
    let mut ctx = hmac_init(key, algorithm)?;
    ctx.digest_sign_update(data)?;
    hmac_final(&mut ctx)
}

/// Hashing algorithm of the HMAC: the request's Hashing Algorithm, else its HMAC
/// Cryptographic Algorithm (KMIP 2.1 Table 259), else inferred from the key.
fn mac_hashing_algorithm(
    key_block: &KeyBlock,
    attrs: &Attributes,
    request_parameters: Option<&CryptographicParameters>,
) -> KResult<HashingAlgorithm> {
    if let Some(cp) = request_parameters {
        if let Some(hashing_algorithm) = cp.hashing_algorithm {
            return Ok(hashing_algorithm);
        }
        if let Some(ca) = cp.cryptographic_algorithm {
            return hmac_algorithm_to_hashing(ca).map_err(|_e| {
                KmsError::Kmip21Error(
                    ErrorReason::Bad_Cryptographic_Parameters,
                    format!("MAC: {ca:?} is not an HMAC algorithm"),
                )
            });
        }
    }
    infer_hmac_hashing_algorithm(key_block, attrs)
}

/// Map a `CryptographicAlgorithm` HMAC variant to its `HashingAlgorithm`.
pub(crate) fn hmac_algorithm_to_hashing(ca: CryptographicAlgorithm) -> KResult<HashingAlgorithm> {
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
fn infer_hmac_hashing_algorithm(
    key_block: &KeyBlock,
    attrs: &Attributes,
) -> KResult<HashingAlgorithm> {
    if let Some(ca) = key_block.cryptographic_algorithm {
        if let Ok(ha) = hmac_algorithm_to_hashing(ca) {
            return Ok(ha);
        }
    }
    // the Cryptographic Algorithm attribute (KMIP 2.1 §4.12) when the key block does not carry it
    if let Some(ca) = attrs.cryptographic_algorithm {
        if let Ok(ha) = hmac_algorithm_to_hashing(ca) {
            return Ok(ha);
        }
    }
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

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_operations::{MAC, MACVerify},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier,
                ValidityIndicator,
            },
            requests::symmetric_key_create_request,
        },
    };

    use crate::{
        config::ServerParams,
        core::{KMS, operations::mac::compute_hmac},
        error::KmsError,
        middlewares::UserId,
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

    fn mac_request(
        uid: &UniqueIdentifier,
        data: Option<&[u8]>,
        correlation_value: Option<Vec<u8>>,
        init_indicator: Option<bool>,
        final_indicator: Option<bool>,
    ) -> MAC {
        MAC {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: data.map(<[u8]>::to_vec),
            correlation_value,
            init_indicator,
            final_indicator,
        }
    }

    #[allow(clippy::unwrap_in_result)]
    #[tokio::test]
    async fn test_server_mac_operation() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::from(ServerParams::try_from(https_clap_config())?)).await?,
        );
        let user = UserId::from("user");

        let uid = kms
            .create(
                symmetric_key_create_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    256,
                    CryptographicAlgorithm::SHA3256,
                    EMPTY_TAGS,
                    false,
                    None,
                )?,
                &user,
            )
            .await?
            .unique_identifier;

        // Single-part reference over the whole message
        let single = kms
            .mac(
                mac_request(&uid, Some(&[1, 2, 3, 4, 5, 6]), None, None, None),
                &user,
            )
            .await?;
        let expected = single.mac_data.unwrap();
        assert_eq!(expected.len(), 32);
        assert_eq!(single.correlation_value, None);

        // Multi-part: init, middle, final must give the same MAC (keyed with the stored key)
        let init = kms
            .mac(
                mac_request(&uid, Some(&[1, 2]), None, Some(true), None),
                &user,
            )
            .await?;
        assert_eq!(init.mac_data, None);
        let cv = init.correlation_value.unwrap();
        let middle = kms
            .mac(
                mac_request(&uid, Some(&[3, 4]), Some(cv.clone()), None, None),
                &user,
            )
            .await?;
        assert_eq!(middle.mac_data, None);
        assert_eq!(middle.correlation_value.as_ref(), Some(&cv));
        let last = kms
            .mac(
                mac_request(&uid, Some(&[5, 6]), Some(cv.clone()), None, Some(true)),
                &user,
            )
            .await?;
        assert_eq!(last.mac_data, Some(expected.clone()));
        assert_eq!(last.correlation_value, None);

        // Multi-part MAC Verify; MAC Data supplied on the initial part
        let verify = |data: &[u8], mac_data: Vec<u8>, cv: Option<Vec<u8>>, init, fin| MACVerify {
            unique_identifier: uid.clone(),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: data.to_vec(),
            mac_data,
            correlation_value: cv,
            init_indicator: init,
            final_indicator: fin,
        };
        let init = kms
            .mac_verify(
                verify(&[1, 2, 3], expected.clone(), None, Some(true), None),
                &user,
            )
            .await?;
        assert_eq!(init.validity_indicator, None);
        let cv = init.correlation_value.unwrap();
        let last = kms
            .mac_verify(
                verify(&[4, 5, 6], Vec::new(), Some(cv), None, Some(true)),
                &user,
            )
            .await?;
        assert_eq!(last.validity_indicator, Some(ValidityIndicator::Valid));

        // Single-part MAC Verify of a wrong MAC
        let mut wrong = expected;
        if let Some(byte) = wrong.first_mut() {
            *byte ^= 1;
        }
        let res = kms
            .mac_verify(verify(&[1, 2, 3, 4, 5, 6], wrong, None, None, None), &user)
            .await?;
        assert_eq!(res.validity_indicator, Some(ValidityIndicator::Invalid));

        // Another user cannot continue the stream; the owner still can afterwards
        let init = kms
            .mac(mac_request(&uid, Some(&[1]), None, Some(true), None), &user)
            .await?;
        let cv = init.correlation_value.unwrap();
        kms.mac(
            mac_request(&uid, Some(&[2]), Some(cv.clone()), None, Some(true)),
            &UserId::from("mallory"),
        )
        .await
        .unwrap_err();
        let last = kms
            .mac(
                mac_request(&uid, Some(&[2]), Some(cv), None, Some(true)),
                &user,
            )
            .await?;
        assert!(last.mac_data.is_some());

        // Single-part MAC requires Data
        let err = kms
            .mac(mac_request(&uid, None, None, None, None), &user)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_server_mac_requires_usage_mask() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::from(ServerParams::try_from(https_clap_config())?)).await?,
        );
        let user = UserId::from("user");
        // AES keys created with the default mask (Encrypt|Decrypt|...) have no MACGenerate bit
        let uid = kms
            .create(
                symmetric_key_create_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    256,
                    CryptographicAlgorithm::AES,
                    EMPTY_TAGS,
                    false,
                    None,
                )?,
                &user,
            )
            .await?
            .unique_identifier;
        let err = kms
            .mac(mac_request(&uid, Some(&[1]), None, None, None), &user)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                KmsError::Kmip21Error(ErrorReason::Incompatible_Cryptographic_Usage_Mask, _)
            ),
            "{err:?}"
        );
        Ok(())
    }

    /// KMIP 2.1 Table 259: the MAC algorithm comes from the key's Cryptographic Algorithm
    /// attribute when the request carries no parameters and the key block holds no algorithm.
    #[test]
    fn hmac_algorithm_is_inferred_from_the_attribute() {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_attributes::Attributes, kmip_data_structures::KeyBlock, kmip_types::KeyFormatType,
        };

        use super::infer_hmac_hashing_algorithm;

        let key_block = KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: None,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        };
        let attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::HMACSHA1),
            ..Attributes::default()
        };
        assert_eq!(
            infer_hmac_hashing_algorithm(&key_block, &attributes).unwrap(),
            HashingAlgorithm::SHA1
        );
        infer_hmac_hashing_algorithm(&key_block, &Attributes::default()).unwrap_err();
    }
}

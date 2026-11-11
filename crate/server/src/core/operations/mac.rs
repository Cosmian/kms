use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{
            BlockCipherMode, CryptographicUsageMask, ErrorReason, HashingAlgorithm, State,
        },
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
    cosmian_kms_crypto::crypto::symmetric::mac::{AesMac, GMAC_IV_LENGTH, gmac_iv},
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
        matches!(owm.object(), Object::SymmetricKey { .. })
            && owm.has_usage_mask(CryptographicUsageMask::MACGenerate, false)
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
        if request.i_v_counter_nonce.is_some()
            && aes_mac_mode(request.cryptographic_parameters.as_ref())?
                != Some(BlockCipherMode::GCM)
        {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "MAC: an IV is only accepted for AES-GMAC (Block Cipher Mode GCM)".to_owned(),
            ));
        }
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
            || {
                mac_context(
                    owm,
                    request.cryptographic_parameters.as_ref(),
                    "mac",
                    || {
                        request
                            .i_v_counter_nonce
                            .as_deref()
                            .map_or_else(|| random_gmac_iv(kms), caller_gmac_iv)
                    },
                )
            },
            |ctx, last| {
                ctx.update(data)?;
                Ok(if last { Some(ctx.finalize()?) } else { None })
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
        if request.i_v_counter_nonce.is_some() {
            kms_bail!(KmsError::NotSupported(
                "MAC: a caller-supplied IV is not supported for HSM keys".to_owned()
            ));
        }
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

/// State of a multi-part MAC Verify: the running MAC and the MAC to check, which may be
/// supplied on the initial or the final part (on the initial part only for AES-GMAC, whose IV
/// it carries).
struct MacVerifyState {
    ctx: MacCtx,
    mac_data: Vec<u8>,
}

/// A running MAC: HMAC, AES-CMAC or AES-GMAC.
enum MacCtx {
    Hmac(MdCtx),
    Aes(AesMac),
}

impl MacCtx {
    fn update(&mut self, data: &[u8]) -> KResult<()> {
        match self {
            Self::Hmac(ctx) => ctx.digest_sign_update(data)?,
            Self::Aes(mac) => mac.update(data)?,
        }
        Ok(())
    }

    fn finalize(&mut self) -> KResult<Vec<u8>> {
        match self {
            Self::Hmac(ctx) => hmac_final(ctx),
            Self::Aes(mac) => Ok(mac.finalize()?),
        }
    }
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
            && owm.has_usage_mask(CryptographicUsageMask::MACVerify, false)
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
                    ctx: mac_context(
                        owm,
                        request.cryptographic_parameters.as_ref(),
                        "mac_verify",
                        || gmac_iv_of(&request.mac_data),
                    )?,
                    mac_data: Vec::new(),
                })
            },
            |state, last| {
                state.ctx.update(&request.data)?;
                if !request.mac_data.is_empty() {
                    state.mac_data.clone_from(&request.mac_data);
                }
                if !last {
                    return Ok(None);
                }
                if state.mac_data.is_empty() {
                    return Err(missing_mac_data());
                }
                let computed = state.ctx.finalize()?;
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
    // memcmp::eq panics on unequal lengths; MAC length is public
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

/// `BlockCipherMode` of an AES MAC requested by `parameters`: CMAC, or GCM for GMAC.
/// `None` selects HMAC.
fn aes_mac_mode(parameters: Option<&CryptographicParameters>) -> KResult<Option<BlockCipherMode>> {
    let Some(parameters) = parameters else {
        return Ok(None);
    };
    let Some(mode @ (BlockCipherMode::CMAC | BlockCipherMode::GCM)) = parameters.block_cipher_mode
    else {
        return Ok(None);
    };
    if let Some(algorithm) = parameters.cryptographic_algorithm
        && algorithm != CryptographicAlgorithm::AES
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Bad_Cryptographic_Parameters,
            format!("MAC: {mode:?} requires the AES cryptographic algorithm, not {algorithm:?}"),
        ));
    }
    Ok(Some(mode))
}

/// Start the MAC of the key of `owm` selected by the request parameters: AES-CMAC, AES-GMAC
/// (with the IV from `gmac_iv`), or else HMAC with the algorithm from the request or the key.
fn mac_context(
    owm: &ObjectWithMetadata,
    request_parameters: Option<&CryptographicParameters>,
    context: &'static str,
    gmac_iv: impl FnOnce() -> KResult<[u8; GMAC_IV_LENGTH]>,
) -> KResult<MacCtx> {
    let key_block = owm.object().key_block()?;
    let key = key_block.key_bytes_ref().context(context)?;
    let Some(mode) = aes_mac_mode(request_parameters)? else {
        let algorithm = mac_hashing_algorithm(key_block, owm.attributes(), request_parameters)?;
        trace!("Mac: algorithm: {algorithm:?}");
        return Ok(MacCtx::Hmac(hmac_init(key, algorithm)?));
    };
    // an HMAC or any other symmetric key must not be usable as an AES MAC key
    if key_block
        .cryptographic_algorithm
        .or_else(|| owm.attributes().cryptographic_algorithm)
        != Some(CryptographicAlgorithm::AES)
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Bad_Cryptographic_Parameters,
            format!("{context}: AES-{mode:?} requires an AES key"),
        ));
    }
    trace!("Mac: AES {mode:?}");
    Ok(MacCtx::Aes(if mode == BlockCipherMode::CMAC {
        AesMac::new_cmac(key)?
    } else {
        AesMac::new_gmac(key, gmac_iv()?)?
    }))
}

/// IV supplied by the caller of an AES-GMAC (PKCS#11 `CKM_AES_GMAC`); it must not repeat
/// under one key, which only the caller can ensure.
fn caller_gmac_iv(iv: &[u8]) -> KResult<[u8; GMAC_IV_LENGTH]> {
    let Ok(iv_array) = <[u8; GMAC_IV_LENGTH]>::try_from(iv) else {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!(
                "MAC: the AES-GMAC IV must be {GMAC_IV_LENGTH} bytes, got {}",
                iv.len()
            ),
        ));
    };
    Ok(iv_array)
}

/// Random IV of a new AES-GMAC.
fn random_gmac_iv(kms: &KMS) -> KResult<[u8; GMAC_IV_LENGTH]> {
    let mut iv = [0_u8; GMAC_IV_LENGTH];
    // the IV is sent in clear with the MAC
    kms.rng.fill_public_bytes(&mut iv)?;
    Ok(iv)
}

/// IV of the AES-GMAC `mac_data` to verify (its first 12 bytes).
fn gmac_iv_of(mac_data: &[u8]) -> KResult<[u8; GMAC_IV_LENGTH]> {
    gmac_iv(mac_data).map_err(|e| {
        KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("MACVerify: AES-GMAC MAC Data is required on the single or initial part: {e}"),
        )
    })
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
    if let Some(ca) = key_block.cryptographic_algorithm
        && let Ok(ha) = hmac_algorithm_to_hashing(ca)
    {
        return Ok(ha);
    }
    // the Cryptographic Algorithm attribute (KMIP 2.1 §4.12) when the key block does not carry it
    if let Some(ca) = attrs.cryptographic_algorithm
        && let Ok(ha) = hmac_algorithm_to_hashing(ca)
    {
        return Ok(ha);
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{
            BlockCipherMode, CryptographicUsageMask, ErrorReason, HashingAlgorithm,
        },
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_operations::{Encrypt, MAC, MACVerify},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier,
                ValidityIndicator,
            },
            requests::symmetric_key_create_request,
        },
    };

    use crate::{
        core::operations::mac::compute_hmac,
        error::KmsError,
        middlewares::UserId,
        result::{KResult, KResultHelper},
        tests::test_utils::test_kms,
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
        assert_ne!(hmac.len(), 0);

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
            assert_ne!(hmac.len(), 0);
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
            i_v_counter_nonce: None,
            correlation_value,
            init_indicator,
            final_indicator,
        }
    }

    #[tokio::test]
    async fn test_server_mac_operation() -> KResult<()> {
        let kms = test_kms().await?;
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

    /// MAC needs the `MACGenerate` usage bit, MAC Verify needs `MACVerify`.
    #[tokio::test]
    async fn test_server_mac_requires_mac_usage_bits() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("user");
        let create = |algorithm, mask: Option<CryptographicUsageMask>| {
            let kms = &kms;
            let user = &user;
            async move {
                let mut request = symmetric_key_create_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    256,
                    algorithm,
                    EMPTY_TAGS,
                    false,
                    None,
                )?;
                if mask.is_some() {
                    request.attributes.cryptographic_usage_mask = mask;
                }
                KResult::Ok(kms.create(request, user).await?.unique_identifier)
            }
        };
        let verify = |uid: &UniqueIdentifier| MACVerify {
            unique_identifier: uid.clone(),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: vec![1],
            mac_data: vec![0; 32],
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let is_mask_error = |error: &KmsError| {
            matches!(
                error,
                KmsError::Kmip21Error(ErrorReason::Incompatible_Cryptographic_Usage_Mask, _)
            )
        };

        // A default AES key carries no MAC bit: both operations are refused.
        let aes = create(CryptographicAlgorithm::AES, None).await?;
        let error = kms
            .mac(mac_request(&aes, Some(&[1]), None, None, None), &user)
            .await
            .unwrap_err();
        assert!(is_mask_error(&error), "{error:?}");
        let error = kms.mac_verify(verify(&aes), &user).await.unwrap_err();
        assert!(is_mask_error(&error), "{error:?}");

        // MACGenerate alone MACs but cannot verify.
        let generate_only = create(
            CryptographicAlgorithm::AES,
            Some(CryptographicUsageMask::MACGenerate),
        )
        .await?;
        kms.mac(
            mac_request(&generate_only, Some(&[1]), None, None, None),
            &user,
        )
        .await?;
        let error = kms
            .mac_verify(verify(&generate_only), &user)
            .await
            .unwrap_err();
        assert!(is_mask_error(&error), "{error:?}");

        // MACGenerate | MACVerify does both.
        let both = create(
            CryptographicAlgorithm::AES,
            Some(CryptographicUsageMask::MACGenerate | CryptographicUsageMask::MACVerify),
        )
        .await?;
        kms.mac(mac_request(&both, Some(&[1]), None, None, None), &user)
            .await?;
        let response = kms.mac_verify(verify(&both), &user).await?;
        assert_eq!(
            response.validity_indicator,
            Some(ValidityIndicator::Invalid)
        );
        Ok(())
    }

    /// Pins the `MACVerify` verdicts. It passes before and after the switch to a
    /// constant-time compare (only timing differs); it guards the verdicts against regressions.
    #[tokio::test]
    async fn test_server_mac_verify_rejects_tampered_mac() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("user");
        let unique_identifier = kms
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
        let mac = kms
            .mac(
                mac_request(&unique_identifier, Some(&[1, 2, 3]), None, None, None),
                &user,
            )
            .await?
            .mac_data
            .context("MAC response has no mac_data")?;

        let mut flipped = mac.clone();
        *flipped.last_mut().context("empty MAC")? ^= 1;
        let mut truncated = mac.clone();
        truncated.pop();

        let verify = |mac_data| MACVerify {
            unique_identifier: unique_identifier.clone(),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..Default::default()
            }),
            data: vec![1, 2, 3],
            mac_data,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        for (mac_data, expected) in [
            (mac, ValidityIndicator::Valid),
            (flipped, ValidityIndicator::Invalid),
            (truncated, ValidityIndicator::Invalid),
        ] {
            let response = kms.mac_verify(verify(mac_data), &user).await?;
            assert_eq!(response.validity_indicator, Some(expected));
        }
        // A single-part MAC Verify without MAC Data is rejected rather than reported Invalid
        let err = kms.mac_verify(verify(vec![]), &user).await.unwrap_err();
        assert!(matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
        ));
        Ok(())
    }

    /// AES-CMAC and AES-GMAC through MAC / MAC Verify: single and multi-part, tampering, and
    /// refusal of a key that is not an AES key.
    #[tokio::test]
    async fn test_server_aes_cmac_and_gmac() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("user");
        let create = |algorithm| {
            let kms = &kms;
            let user = &user;
            async move {
                let mut request = symmetric_key_create_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    256,
                    algorithm,
                    EMPTY_TAGS,
                    false,
                    None,
                )?;
                request.attributes.cryptographic_usage_mask = Some(
                    CryptographicUsageMask::MACGenerate
                        | CryptographicUsageMask::MACVerify
                        | CryptographicUsageMask::Encrypt,
                );
                KResult::Ok(kms.create(request, user).await?.unique_identifier)
            }
        };
        let aes = create(CryptographicAlgorithm::AES).await?;
        let parameters = |mode| {
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(mode),
                ..Default::default()
            })
        };
        let mac = |uid: &UniqueIdentifier, mode, data: &[u8], cv, init, fin| MAC {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: parameters(mode),
            data: Some(data.to_vec()),
            i_v_counter_nonce: None,
            correlation_value: cv,
            init_indicator: init,
            final_indicator: fin,
        };
        let verify =
            |uid: &UniqueIdentifier, mode, data: &[u8], mac_data, cv, init, fin| MACVerify {
                unique_identifier: uid.clone(),
                cryptographic_parameters: parameters(mode),
                data: data.to_vec(),
                mac_data,
                correlation_value: cv,
                init_indicator: init,
                final_indicator: fin,
            };

        for (mode, mac_len) in [(BlockCipherMode::CMAC, 16), (BlockCipherMode::GCM, 28)] {
            let single = kms
                .mac(mac(&aes, mode, b"hello world", None, None, None), &user)
                .await?
                .mac_data
                .context("no MAC")?;
            assert_eq!(single.len(), mac_len);

            let verdict = |data: &'static [u8], mac_data: Vec<u8>| {
                let request = verify(&aes, mode, data, mac_data, None, None, None);
                let kms = &kms;
                let user = &user;
                async move { KResult::Ok(kms.mac_verify(request, user).await?.validity_indicator) }
            };
            assert_eq!(
                verdict(b"hello world", single.clone()).await?,
                Some(ValidityIndicator::Valid)
            );
            // tampered data, tag and (GMAC) IV
            let mut bad_tag = single.clone();
            *bad_tag.last_mut().context("empty MAC")? ^= 1;
            let mut bad_head = single.clone();
            bad_head[0] ^= 1;
            for (data, mac_data) in [
                (&b"hello worle"[..], single.clone()),
                (&b"hello world"[..], bad_tag),
                (&b"hello world"[..], bad_head),
            ] {
                assert_eq!(
                    verdict(data, mac_data).await?,
                    Some(ValidityIndicator::Invalid)
                );
            }

            // multi-part MAC Verify, MAC Data on the initial part
            let init = kms
                .mac_verify(
                    verify(
                        &aes,
                        mode,
                        b"hello ",
                        single.clone(),
                        None,
                        Some(true),
                        None,
                    ),
                    &user,
                )
                .await?;
            let last = kms
                .mac_verify(
                    verify(
                        &aes,
                        mode,
                        b"world",
                        Vec::new(),
                        init.correlation_value,
                        None,
                        Some(true),
                    ),
                    &user,
                )
                .await?;
            assert_eq!(last.validity_indicator, Some(ValidityIndicator::Valid));

            // multi-part MAC, checked against the one-shot verification
            let init = kms
                .mac(mac(&aes, mode, b"hello ", None, Some(true), None), &user)
                .await?;
            let last = kms
                .mac(
                    mac(
                        &aes,
                        mode,
                        b"world",
                        init.correlation_value,
                        None,
                        Some(true),
                    ),
                    &user,
                )
                .await?
                .mac_data
                .context("no MAC")?;
            assert_eq!(last.len(), mac_len);
            assert_eq!(
                verdict(b"hello world", last).await?,
                Some(ValidityIndicator::Valid)
            );
        }

        // GMAC: a MAC that is not IV || tag cannot carry an IV
        let error = kms
            .mac_verify(
                verify(
                    &aes,
                    BlockCipherMode::GCM,
                    b"x",
                    vec![0; 16],
                    None,
                    None,
                    None,
                ),
                &user,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
        ));

        // GMAC multi-part verify needs the MAC Data (it carries the IV) on the initial part
        let error = kms
            .mac_verify(
                verify(
                    &aes,
                    BlockCipherMode::GCM,
                    b"x",
                    Vec::new(),
                    None,
                    Some(true),
                    None,
                ),
                &user,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
        ));

        // A caller-supplied IV (PKCS#11 `CKM_AES_GMAC`): the MAC is that IV followed by the tag,
        // it is repeatable, and equals the tag of AES-GCM of an empty plaintext with the data as
        // AAD.
        let iv = [0x42_u8; 12];
        let with_iv = |mode, iv: &[u8]| MAC {
            i_v_counter_nonce: Some(iv.to_vec()),
            ..mac(&aes, mode, b"hello world", None, None, None)
        };
        let gmac = kms
            .mac(with_iv(BlockCipherMode::GCM, &iv), &user)
            .await?
            .mac_data
            .context("no MAC")?;
        assert_eq!(gmac.get(..12), Some(iv.as_slice()));
        assert_eq!(
            kms.mac(with_iv(BlockCipherMode::GCM, &iv), &user)
                .await?
                .mac_data,
            Some(gmac.clone())
        );
        let encrypted = kms
            .encrypt(
                Encrypt {
                    unique_identifier: Some(aes.clone()),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        ..Default::default()
                    }),
                    data: Some(zeroize::Zeroizing::new(Vec::new())),
                    i_v_counter_nonce: Some(iv.to_vec()),
                    authenticated_encryption_additional_data: Some(b"hello world".to_vec()),
                    ..Default::default()
                },
                &user,
            )
            .await?;
        assert_eq!(
            encrypted.authenticated_encryption_tag.as_deref(),
            gmac.get(12..)
        );
        // the IV is only for GMAC and must be 96 bits
        for (mode, bad_iv) in [
            (BlockCipherMode::GCM, &iv[..11]),
            (BlockCipherMode::GCM, &[0_u8; 16][..]),
            (BlockCipherMode::CMAC, &iv[..]),
        ] {
            let error = kms.mac(with_iv(mode, bad_iv), &user).await.unwrap_err();
            assert!(
                matches!(error, KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)),
                "{mode:?} {}: {error:?}",
                bad_iv.len()
            );
        }

        // An HMAC key is not an AES MAC key
        let hmac_key = create(CryptographicAlgorithm::HMACSHA256).await?;
        for mode in [BlockCipherMode::CMAC, BlockCipherMode::GCM] {
            let error = kms
                .mac(mac(&hmac_key, mode, b"x", None, None, None), &user)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    KmsError::Kmip21Error(ErrorReason::Bad_Cryptographic_Parameters, _)
                ),
                "{error:?}"
            );
        }
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

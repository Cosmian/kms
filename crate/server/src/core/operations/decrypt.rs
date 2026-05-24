use std::borrow::Cow;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::{
        DecryptionSystem, cover_crypt::decryption::CovercryptDecryption,
        elliptic_curves::ecies::ecies_decrypt, rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_decrypt,
    },
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, PaddingMethod},
        kmip_2_1::{
            KmipOperation,
            extra::BulkData,
            kmip_objects::Object,
            kmip_operations::{Decrypt, DecryptResponse},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
            },
        },
    },
    cosmian_kms_crypto::{
        crypto::{
            rsa::{
                ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_unwrap,
                ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_decrypt, default_cryptographic_parameters,
            },
            symmetric::symmetric_ciphers::{SymCipher, decrypt as sym_decrypt},
        },
        openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::{CryptoAlgorithm, ObjectWithMetadata},
};
use cosmian_logger::{debug, info, trace};
use openssl::pkey::{Id, PKey, Private};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::enforce_ecies_fixed_suite_for_attributes;
use crate::{
    config::ServerParams,
    core::{
        KMS,
        operations::{CryptoOpSpec, ResolvedKey, has_usage_mask, resolve_key_for_operation},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

/// Marker type for the Decrypt operation's key selection requirements.
pub(crate) struct DecryptOp;

impl CryptoOpSpec for DecryptOp {
    const KMIP_OP: KmipOperation = KmipOperation::Decrypt;
    const OP_NAME: &'static str = "Decrypt";
    const SUPPORTS_ORACLE: bool = true;

    fn is_key_eligible(owm: &ObjectWithMetadata, vendor_id: &str) -> bool {
        #[cfg(not(feature = "non-fips"))]
        let _ = vendor_id;
        if let Object::SymmetricKey { .. } = owm.object() {
            return has_usage_mask(owm, CryptographicUsageMask::Decrypt, false);
        }
        if let Object::PrivateKey { .. } = owm.object() {
            if !has_usage_mask(owm, CryptographicUsageMask::Decrypt, false) {
                return false;
            }
            #[cfg(feature = "non-fips")]
            if owm
                .object()
                .attributes()
                .unwrap_or_else(|_| owm.attributes())
                .key_format_type
                == Some(KeyFormatType::CoverCryptSecretKey)
            {
                use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::access_policy_from_attributes;
                let attributes = owm
                    .object()
                    .attributes()
                    .unwrap_or_else(|_| owm.attributes());
                if access_policy_from_attributes(vendor_id, attributes).is_err() {
                    return false;
                }
            }
            return true;
        }
        false
    }

    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        user: &str,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) => KmsError::ItemNotFound(format!(
                "Decrypt: failed to retrieve the key: {unique_identifier}"
            )),
            KmsError::Unauthorized(_) => KmsError::Unauthorized(format!(
                "Decrypt: the user {user} does not have the permission to decrypt using the key: \
                 {unique_identifier}"
            )),
            other => other,
        }
    }
}

pub(crate) async fn decrypt(kms: &KMS, request: Decrypt, user: &str) -> KResult<DecryptResponse> {
    trace!(
        "Decrypt: uid={:?}, data_len={}",
        request.unique_identifier,
        request.data.as_ref().map_or(0, Vec::len)
    );
    let data = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    match resolve_key_for_operation::<DecryptOp>(unique_identifier, kms, user).await? {
        ResolvedKey::Oracle { uid, prefix } => {
            debug!("{user} is authorized to decrypt using: {uid} from crypto oracle");
            return decrypt_using_crypto_oracle(kms, &request, &uid, &prefix).await;
        }
        ResolvedKey::Local(owm) => {
            let mut owm = *owm;
            // Unwrap + second-stage enforcement.
            super::unwrap_and_enforce_policy(kms, &mut owm, "Decrypt", user)
                .await
                .with_context(|| format!("Decrypt: the key: {}, cannot be unwrapped.", owm.id()))?;

            let ciphertext_len = request.data.as_ref().map_or(0, Vec::len);

            // Enforce UsageLimits before the operation.
            super::enforce_usage_limits(&owm, ciphertext_len)?;

            let res = BulkData::deserialize(data).map_or_else(
                |_| decrypt_single(&owm, &kms.params, &request),
                |bulk_data| decrypt_bulk(&owm, &kms.params, &request, bulk_data),
            )?;

            // Post-operation: decrement and persist usage limits.
            super::decrement_usage_limits(kms, &mut owm, "Decrypt", ciphertext_len).await?;

            info!(
                uid = owm.id(),
                user = user,
                "Decrypted ciphertext of: {} bytes -> plaintext length: {}",
                ciphertext_len,
                res.data.as_ref().map_or(0, |d| d.len()),
            );

            Ok(res)
        }
    }
}

/// Decrypt using a decryption oracle.
///
/// # Arguments
/// * `kms` - the KMS
/// * `request` - the decrypt request
/// * `uid` - the unique identifier of the key
/// * `prefix` - the prefix of the decryption oracle
///
/// # Returns
/// * the decrypt response
async fn decrypt_using_crypto_oracle(
    kms: &KMS,
    request: &Decrypt,
    uid: &str,
    prefix: &str,
) -> KResult<DecryptResponse> {
    let mut data = request
        .i_v_counter_nonce
        .as_ref()
        .map_or(vec![], Clone::clone);
    data.extend(
        request
            .data
            .as_ref()
            .ok_or_else(|| {
                KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
            })?
            .clone(),
    );
    if let Some(tag) = &request.authenticated_encryption_tag {
        data.extend(tag.iter().copied());
    }
    debug!(
        "Encryption Oracle for prefix: {prefix}, total ciphertext is {} bytes long",
        data.len()
    );
    let cleartext = kms
        .crypto_oracles
        .read()
        .await
        .get(prefix)
        .ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "Decrypt: unknown decryption oracle prefix: {prefix}"
            ))
        })?
        .decrypt(
            uid,
            data.as_slice(),
            request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| CryptoAlgorithm::from_kmip(cp).transpose())
                .transpose()?,
            request.authenticated_encryption_additional_data.as_deref(),
        )
        .await?;
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        data: Some(cleartext),
        correlation_value: request.correlation_value.clone(),
    })
}

fn decrypt_bulk(
    owm: &ObjectWithMetadata,
    server_params: &ServerParams,
    request: &Decrypt,
    bulk_data: BulkData,
) -> KResult<DecryptResponse> {
    debug!(
        "decrypt_bulk: ==> decrypting {} ciphertexts",
        bulk_data.len()
    );
    let key_block = owm.object().key_block()?;
    let mut plaintexts = Vec::with_capacity(bulk_data.len());

    match &key_block.key_format_type {
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptSecretKey => {
            for ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                let request = Decrypt {
                    data: Some(ciphertext.to_vec()),
                    ..request.clone()
                };
                let response = decrypt_with_covercrypt(owm, &request)?;
                plaintexts.push(response.data.unwrap_or_default());
            }
        }

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            for ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                let request = Decrypt {
                    data: Some(ciphertext.to_vec()),
                    ..request.clone()
                };
                let response = decrypt_with_private_key(owm, &request, server_params)?;
                plaintexts.push(response.data.unwrap_or_default());
            }
        }

        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            let (key_bytes, sym_cipher) = get_aead_and_key(owm, request)?;
            for nonce_ciphertext_tag in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data)
            {
                if nonce_ciphertext_tag.len() < sym_cipher.nonce_size() + sym_cipher.tag_size() {
                    return Err(KmsError::InvalidRequest(
                        "Decrypt bulk: invalid nonce/ciphertext/tag length".to_owned(),
                    ));
                }
                let nonce = &nonce_ciphertext_tag
                    .get(0..sym_cipher.nonce_size())
                    .ok_or_else(|| {
                        KmsError::ServerError(
                            "Decrypt bulk: indexing slicing failed for nonce".to_owned(),
                        )
                    })?;
                let ciphertext = &nonce_ciphertext_tag
                    .get(
                        sym_cipher.nonce_size()..nonce_ciphertext_tag.len() - sym_cipher.tag_size(),
                    )
                    .ok_or_else(|| {
                        KmsError::ServerError(
                            "Decrypt bulk: indexing slicing failed for ciphertext".to_owned(),
                        )
                    })?;
                let tag = nonce_ciphertext_tag
                    .get(nonce_ciphertext_tag.len() - sym_cipher.tag_size()..)
                    .ok_or_else(|| {
                        KmsError::ServerError(
                            "Decrypt bulk: indexing slicing failed for tag".to_owned(),
                        )
                    })?;
                let padding_method = request
                    .cryptographic_parameters
                    .as_ref()
                    .and_then(|cp| cp.padding_method)
                    .unwrap_or(PaddingMethod::PKCS5);
                let plaintext = sym_decrypt(
                    sym_cipher,
                    &key_bytes,
                    nonce,
                    &[],
                    ciphertext,
                    tag,
                    Some(padding_method),
                )?;
                plaintexts.push(plaintext);
            }
        }

        other => {
            return Err(KmsError::NotSupported(format!(
                "decryption with keys of format: {other}"
            )));
        }
    }

    debug!(
        "decrypt_bulk: ==> decrypted {} plaintexts",
        plaintexts.len()
    );
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(BulkData::new(plaintexts).serialize()?),
        correlation_value: request.correlation_value.clone(),
    })
}

fn decrypt_single(
    owm: &ObjectWithMetadata,
    server_params: &crate::config::ServerParams,
    request: &Decrypt,
) -> KResult<DecryptResponse> {
    trace!("Extracting key block for decryption to identify key format type...");
    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        #[cfg(feature = "non-fips")]
        KeyFormatType::ConfigurableKEMSecretKey => {
            use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::kem::kem_decaps;

            let (dk_bytes, _) = owm.object().key_block()?.key_bytes_and_attributes()?;
            let enc = request
                .data
                .as_ref()
                .ok_or_else(|| KmsError::InvalidRequest("missing KEM encapsulation".to_owned()))?;
            let key = kem_decaps(&dk_bytes, enc)?;
            Ok(DecryptResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                data: Some(key),
                correlation_value: None,
            })
        }
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptSecretKey => decrypt_with_covercrypt(owm, request),

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8
        | KeyFormatType::Raw => {
            // Check for KEM: if the key's algorithm is ML-KEM or hybrid KEM, perform decapsulation
            // instead of standard decryption.
            #[cfg(feature = "non-fips")]
            {
                let key_algo = key_block
                    .cryptographic_algorithm()
                    .copied()
                    .or_else(|| owm.attributes().cryptographic_algorithm);
                if matches!(
                    key_algo,
                    Some(
                        CryptographicAlgorithm::MLKEM_512
                            | CryptographicAlgorithm::MLKEM_768
                            | CryptographicAlgorithm::MLKEM_1024
                    )
                ) {
                    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::ml_kem::ml_kem_decapsulate;
                    let ciphertext = request.data.as_ref().ok_or_else(|| {
                        KmsError::InvalidRequest(
                            "Decrypt ML-KEM: ciphertext (encapsulation) must be provided"
                                .to_owned(),
                        )
                    })?;
                    let (priv_bytes, _) = key_block.key_bytes_and_attributes()?;
                    let shared_secret = ml_kem_decapsulate(&priv_bytes, ciphertext)?;
                    return Ok(DecryptResponse {
                        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                        data: Some(Zeroizing::from(shared_secret)),
                        correlation_value: request.correlation_value.clone(),
                    });
                }
                if let Some(
                    algo @ (CryptographicAlgorithm::X25519MLKEM768
                    | CryptographicAlgorithm::X448MLKEM1024),
                ) = key_algo
                {
                    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::hybrid_kem::hybrid_kem_decapsulate;
                    let ciphertext = request.data.as_ref().ok_or_else(|| {
                        KmsError::InvalidRequest(
                            "Decrypt hybrid KEM: ciphertext (encapsulation) must be provided"
                                .to_owned(),
                        )
                    })?;
                    let (priv_bytes, _) = key_block.key_bytes_and_attributes()?;
                    let shared_secret = hybrid_kem_decapsulate(algo, &priv_bytes, ciphertext)?;
                    return Ok(DecryptResponse {
                        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                        data: Some(Zeroizing::from(shared_secret)),
                        correlation_value: request.correlation_value.clone(),
                    });
                }
            }

            // Raw format can be either a private key or a symmetric key;
            // route symmetric keys to the correct handler.
            if matches!(owm.object(), Object::SymmetricKey { .. }) {
                return decrypt_single_with_symmetric_key(owm, request)?;
            }

            trace!(
                "matching on public key format type: {:?}",
                key_block.key_format_type
            );
            decrypt_with_private_key(owm, request, server_params)
        }

        KeyFormatType::TransparentSymmetricKey => decrypt_single_with_symmetric_key(owm, request)?,

        other => Err(KmsError::NotSupported(format!(
            "decryption with keys of format: {other}"
        ))),
    }
}

#[cfg(feature = "non-fips")]
fn decrypt_with_covercrypt(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<DecryptResponse, KmsError> {
    trace!("key id {}", owm.id());
    CovercryptDecryption::instantiate(Covercrypt::default(), owm.id(), owm.object())?
        .decrypt(request)
        .map_err(Into::into)
}

fn decrypt_single_with_symmetric_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<Result<DecryptResponse, KmsError>, KmsError> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Decrypt single with symmetric key: data to decrypt must be provided".to_owned(),
        )
    })?;
    let (key_bytes, aead) = get_aead_and_key(owm, request)?;
    trace!(
        "got key bytes of length: {}, aead: {:?}. Proceeding to get the nonce...",
        key_bytes.len(),
        aead
    );
    // For modes with nonce_size()==0 (e.g. ECB) we do not expect / require an IV.
    // For modes with nonce_size()>0 we require an IV. Some KMIP vectors supply an empty
    // IVCounterNonce element to indicate an all-zero IV (e.g. CBC test cases). Treat a
    // present-but-empty value as a zero IV of the required size. Any other length mismatch
    // is reported as Invalid_Message instead of triggering an OpenSSL panic.
    let empty_nonce_storage = Vec::new();
    let nonce_storage: Cow<[u8]> = if aead.nonce_size() == 0 {
        Cow::Borrowed(&empty_nonce_storage)
    } else {
        let provided = request.i_v_counter_nonce.as_ref().ok_or_else(|| {
            KmsError::Kmip21Error(ErrorReason::Invalid_Message, "missing-iv".to_owned())
        })?;
        if provided.is_empty() {
            // Interpret empty provided IV as an all-zero IV of the recommended size for the cipher.
            Cow::Owned(vec![0_u8; aead.nonce_size()])
        } else if provided.len() == aead.nonce_size() {
            Cow::Borrowed(provided)
        } else {
            // Length mismatch: allow variable length only for AES-GCM (per spec and OpenSSL support).
            match aead {
                SymCipher::Aes128Gcm | SymCipher::Aes192Gcm | SymCipher::Aes256Gcm => {
                    // Accept any non-empty length; pass through unchanged. (OpenSSL derives J0 for non-96-bit IVs.)
                    Cow::Borrowed(provided)
                }
                _ => {
                    return Ok(Err(KmsError::Kmip21Error(
                        ErrorReason::Invalid_Message,
                        format!(
                            "invalid-iv-length: expected {} got {}",
                            aead.nonce_size(),
                            provided.len()
                        ),
                    )));
                }
            }
        }
    };
    let nonce: &[u8] = nonce_storage.as_ref();
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let tag = if aead.tag_size() == 0 {
        EMPTY_SLICE
    } else {
        request
            .authenticated_encryption_tag
            .as_deref()
            .unwrap_or(EMPTY_SLICE)
    };
    let padding_method = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.padding_method)
        .unwrap_or(match aead {
            SymCipher::Aes128Ecb | SymCipher::Aes192Ecb | SymCipher::Aes256Ecb => {
                PaddingMethod::None
            }
            _ => PaddingMethod::PKCS5,
        });
    if aead.nonce_size() == 0 {
        trace!(
            "ciphertext (ECB): {ciphertext:?}, aad: {aad:?}, padding_method: {padding_method:?}"
        );
    } else {
        trace!(
            "ciphertext: {ciphertext:?}, nonce: {nonce:?}, aad: {aad:?}, tag: {tag:?}, \
             padding_method: {padding_method:?}"
        );
    }
    let plaintext = sym_decrypt(
        aead,
        &key_bytes,
        nonce,
        aad,
        ciphertext,
        tag,
        Some(padding_method),
    )?;
    trace!("plaintext length: {} bytes", plaintext.len());
    Ok(Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(plaintext),
        correlation_value: request.correlation_value.clone(),
    }))
}

fn get_aead_and_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<(Zeroizing<Vec<u8>>, SymCipher), KmsError> {
    let key_block = owm.object().key_block()?;
    // recover the cryptographic algorithm from the request or the key block or default to AES
    let cryptographic_algorithm = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.cryptographic_algorithm)
        .or_else(|| {
            owm.attributes()
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.cryptographic_algorithm)
        })
        .unwrap_or_else(|| {
            key_block
                .cryptographic_algorithm()
                .copied()
                .unwrap_or(CryptographicAlgorithm::AES)
        });
    // Fallback to stored key block mode if request omitted it (e.g., ECB cases)
    let block_cipher_mode = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.block_cipher_mode)
        .or_else(|| {
            owm.attributes()
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.block_cipher_mode)
        });
    let key_bytes = key_block.key_bytes()?;
    let aead = SymCipher::from_algorithm_and_key_size(
        cryptographic_algorithm,
        block_cipher_mode,
        key_bytes.len(),
    )?;
    Ok((key_bytes, aead))
}

fn decrypt_with_private_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
    #[cfg(feature = "non-fips")] server_params: &ServerParams,
    #[cfg(not(feature = "non-fips"))] _server_params: &ServerParams,
) -> KResult<DecryptResponse> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;
    let private_key = kmip_private_key_to_openssl(owm.object())?;
    // Merge stored key cryptographic parameters with request-provided parameters.
    // Request overrides stored; if request absent, use stored.
    let stored_cp = owm.attributes().cryptographic_parameters.as_ref();
    let effective_cp =
        merge_cryptographic_parameters(stored_cp, request.cryptographic_parameters.as_ref());
    if let Some(cp) = &effective_cp {
        trace!(
            "effective RSA CP -> padding={:?} hashing={:?} mgf1={:?} label_len={}",
            cp.padding_method,
            cp.hashing_algorithm,
            cp.mask_generator_hashing_algorithm,
            cp.p_source.as_ref().map_or(0, std::vec::Vec::len)
        );
    } else {
        trace!("no effective cryptographic parameters; defaults will apply");
    }

    let plaintext = match private_key.id() {
        Id::RSA => decrypt_with_rsa(&private_key, effective_cp.as_ref(), ciphertext)?,
        #[cfg(feature = "non-fips")]
        Id::EC | Id::X25519 | Id::ED25519 => {
            enforce_ecies_fixed_suite_for_attributes(
                server_params,
                "Decrypt",
                owm.id(),
                owm.attributes(),
            )?;
            ecies_decrypt(&private_key, ciphertext)?
        }
        other => {
            kms_bail!("Decrypt with PKey: private key type not supported: {other:?}")
        }
    };
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(plaintext),
        correlation_value: request.correlation_value.clone(),
    })
}

/// Merge stored (from key attributes) and request cryptographic parameters.
/// Request fields, when present, override stored ones; absent request uses stored.
fn merge_cryptographic_parameters(
    stored: Option<&CryptographicParameters>,
    request: Option<&CryptographicParameters>,
) -> Option<CryptographicParameters> {
    match (stored, request) {
        (None, None) => None,
        (Some(s), None) => Some(s.clone()),
        (None, Some(r)) => Some(r.clone()),
        (Some(s), Some(r)) => Some(CryptographicParameters {
            block_cipher_mode: r.block_cipher_mode.or(s.block_cipher_mode),
            padding_method: r.padding_method.or(s.padding_method),
            hashing_algorithm: r.hashing_algorithm.or(s.hashing_algorithm),
            key_role_type: r.key_role_type.or(s.key_role_type),
            digital_signature_algorithm: r
                .digital_signature_algorithm
                .or(s.digital_signature_algorithm),
            cryptographic_algorithm: r.cryptographic_algorithm.or(s.cryptographic_algorithm),
            random_iv: r.random_iv.or(s.random_iv),
            iv_length: r.iv_length.or(s.iv_length),
            tag_length: r.tag_length.or(s.tag_length),
            fixed_field_length: r.fixed_field_length.or(s.fixed_field_length),
            invocation_field_length: r.invocation_field_length.or(s.invocation_field_length),
            counter_length: r.counter_length.or(s.counter_length),
            initial_counter_value: r.initial_counter_value.or(s.initial_counter_value),
            salt_length: r.salt_length.or(s.salt_length),
            mask_generator: r.mask_generator.or(s.mask_generator),
            mask_generator_hashing_algorithm: r
                .mask_generator_hashing_algorithm
                .or(s.mask_generator_hashing_algorithm),
            p_source: r.p_source.clone().or_else(|| s.p_source.clone()),
            trailer_field: r.trailer_field.or(s.trailer_field),
        }),
    }
}

fn decrypt_with_rsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    ciphertext: &[u8],
) -> KResult<Zeroizing<Vec<u8>>> {
    let (algorithm, padding, hashing_fn, _) =
        default_cryptographic_parameters(cryptographic_parameters);
    // MGF1 hash may be specified separately
    let (mgf1_hash_fn, label) = cryptographic_parameters.map_or((hashing_fn, None), |cp| {
        (
            cp.mask_generator_hashing_algorithm.unwrap_or(hashing_fn),
            cp.p_source.as_deref(),
        )
    });
    trace!(
        "algorithm: {:?}, padding: {:?}, hashing_fn: {:?}",
        algorithm, padding, hashing_fn
    );

    Ok(match (algorithm, padding) {
        (CryptographicAlgorithm::RSA, PaddingMethod::None) => {
            ckm_rsa_aes_key_unwrap(private_key, hashing_fn, ciphertext)?
        }
        (CryptographicAlgorithm::RSA, PaddingMethod::OAEP) => {
            ckm_rsa_pkcs_oaep_key_decrypt(private_key, hashing_fn, mgf1_hash_fn, label, ciphertext)?
        }
        #[cfg(feature = "non-fips")]
        (CryptographicAlgorithm::RSA, PaddingMethod::PKCS1v15) => {
            ckm_rsa_pkcs_decrypt(private_key, ciphertext)?
        }
        _ => kms_bail!("Decrypt: algorithm or padding method not supported for RSA decryption"),
    })
}

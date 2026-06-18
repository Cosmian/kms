use std::borrow::Cow;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::{
        DecryptionSystem, cover_crypt::decryption::CovercryptDecryption,
        elliptic_curves::ecies::ecies_decrypt, fpe::decrypt_fpe,
        rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_decrypt,
    },
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, PaddingMethod, State},
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
use cosmian_logger::{debug, trace};
use openssl::pkey::{Id, PKey, Private};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::enforce_ecies_fixed_suite_for_attributes;
use crate::{
    config::ServerParams,
    core::{
        KMS,
        operations::{CryptoOpSpec, KeysetMode, has_usage_mask, perform_crypto_operation},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

const EMPTY_SLICE: &[u8] = &[];

/// Marker type for the Decrypt operation's key selection requirements.
pub(crate) struct DecryptOp;

impl CryptoOpSpec for DecryptOp {
    type Request = Decrypt;
    type Response = DecryptResponse;

    const KMIP_OP: KmipOperation = KmipOperation::Decrypt;
    const OP_NAME: &'static str = "Decrypt";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        request.unique_identifier.as_ref()
    }

    fn keyset_mode() -> KeysetMode {
        KeysetMode::TryEach
    }

    /// Decrypt accepts Active, Deactivated, and Compromised keys per KMIP 2.1 §3.31:
    /// "The object SHALL NOT be used for applying cryptographic protection [...]
    /// The object SHOULD only be used to process cryptographically-protected information."
    fn accepted_states() -> &'static [State] {
        &[State::Active, State::Deactivated, State::Compromised]
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request.data.as_ref().map_or(0, Vec::len)
    }

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

    async fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        _user: &str,
    ) -> KResult<Self::Response> {
        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
        })?;
        BulkData::deserialize(data).map_or_else(
            |_| decrypt_single(owm, &kms.params, request),
            |bulk_data| decrypt_bulk(owm, &kms.params, request, bulk_data),
        )
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
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
            "Decryption Oracle for prefix: {prefix}, total ciphertext is {} bytes long",
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
}

pub(crate) async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
) -> KResult<(DecryptResponse, Option<u32>)> {
    trace!(
        "Decrypt: uid={:?}, data_len={}",
        request.unique_identifier,
        request.data.as_ref().map_or(0, Vec::len)
    );
    Box::pin(perform_crypto_operation::<DecryptOp>(kms, request, user)).await
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
    let key_block = owm.object().key_block()?;
    let stored_cp = owm.attributes().cryptographic_parameters.as_ref();
    let req_cp = request.cryptographic_parameters.as_ref();
    let cryptographic_algorithm = req_cp
        .and_then(|cp| cp.cryptographic_algorithm)
        .or_else(|| stored_cp.and_then(|cp| cp.cryptographic_algorithm))
        .or_else(|| key_block.cryptographic_algorithm().copied())
        .unwrap_or(CryptographicAlgorithm::AES);

    #[cfg(not(feature = "non-fips"))]
    if cryptographic_algorithm == CryptographicAlgorithm::FPE_FF1 {
        return Ok(Err(KmsError::NotSupported(
            "FPE_FF1 decryption is not supported in FIPS mode".to_owned(),
        )));
    }

    #[cfg(feature = "non-fips")]
    if cryptographic_algorithm == CryptographicAlgorithm::FPE_FF1 {
        let ciphertext = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
        })?;
        let plaintext = decrypt_fpe(
            &key_block.key_bytes()?,
            ciphertext,
            request.authenticated_encryption_additional_data.as_deref(),
            request.i_v_counter_nonce.as_deref(),
        )
        .map_err(|e| KmsError::CryptographicError(format!("FPE decrypt failed: {e}")))?;
        return Ok(Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            data: Some(Zeroizing::from(plaintext)),
            correlation_value: request.correlation_value.clone(),
        }));
    }

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
    // For modes with nonce_size()>0 we require an IV.
    //   - Absent IVCounterNonce (None)  → Invalid_Message "missing-iv" (KMIP mandatory compliance).
    //   - Present but empty (Some([]))  → all-zero IV of the required size (some clients send this
    //     explicitly to request a zero IV).
    //   - Correct length               → use as-is.
    //   - Wrong length for GCM         → pass through (OpenSSL derives J0 for non-96-bit IVs).
    //   - Wrong length for other modes → Invalid_Message "invalid-iv-length".
    let empty_nonce_storage = Vec::new();
    let nonce_storage: Cow<[u8]> = if aead.nonce_size() == 0 {
        Cow::Borrowed(&empty_nonce_storage)
    } else {
        let provided = request.i_v_counter_nonce.as_ref();
        if provided.is_none() {
            // IVCounterNonce completely absent — required field; reject per KMIP spec.
            return Ok(Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                "missing-iv".to_owned(),
            )));
        } else if provided.is_some_and(Vec::is_empty) {
            // Explicitly empty IVCounterNonce → caller requests all-zero IV.
            Cow::Owned(vec![0_u8; aead.nonce_size()])
        } else if let Some(iv) = provided.filter(|v| v.len() == aead.nonce_size()) {
            Cow::Borrowed(iv)
        } else {
            // Length mismatch: allow variable length only for AES-GCM (per spec and OpenSSL support).
            // `provided` is guaranteed Some and non-empty at this point (None and empty were
            // handled above), but we retain the let-else for exhaustive safety.
            let Some(iv) = provided else {
                return Ok(Err(KmsError::Kmip21Error(
                    ErrorReason::Invalid_Message,
                    "internal: IV unexpectedly absent after checks".to_owned(),
                )));
            };
            match aead {
                SymCipher::Aes128Gcm | SymCipher::Aes192Gcm | SymCipher::Aes256Gcm => {
                    // Accept any non-empty length; pass through unchanged. (OpenSSL derives J0 for non-96-bit IVs.)
                    Cow::Borrowed(iv)
                }
                _ => {
                    return Ok(Err(KmsError::Kmip21Error(
                        ErrorReason::Invalid_Message,
                        format!(
                            "invalid-iv-length: expected {} got {}",
                            aead.nonce_size(),
                            iv.len()
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
    // Prevent FPE_FF1 keys from being misused for standard symmetric operations.
    // FPE_FF1 decryption is handled before this point; reaching here with an FPE_FF1
    // key means the caller explicitly requested a different algorithm, which is a misuse.
    if key_block.cryptographic_algorithm().copied() == Some(CryptographicAlgorithm::FPE_FF1) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "an FPE_FF1 key may only be used for FPE_FF1 decrypt operations".to_owned(),
        ));
    }
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

use std::borrow::Cow;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::EncryptionSystem;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::ecies::ecies_encrypt;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::fpe::encrypt_fpe;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_encrypt;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::cover_crypt::encryption::CoverCryptEncryption,
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        KmipError,
        kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask, ErrorReason, PaddingMethod},
        kmip_2_1::{
            KmipOperation,
            extra::BulkData,
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object},
            kmip_operations::{Encrypt, EncryptResponse},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
            },
        },
    },
    cosmian_kms_crypto::{
        crypto::{
            KmsRng,
            rsa::{
                ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
                ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_encrypt, default_cryptographic_parameters,
            },
            symmetric::symmetric_ciphers::{SymCipher, encrypt as sym_encrypt, random_nonce},
        },
        openssl::kmip_public_key_to_openssl,
    },
    cosmian_kms_interfaces::{CryptoAlgorithm, ObjectWithMetadata},
};
use cosmian_logger::{debug, trace};
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use zeroize::Zeroizing;

use super::pgp_ops;
#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::{
    enforce_ecies_fixed_suite_for_attributes, enforce_ecies_fixed_suite_for_pkey_id,
};
use crate::{
    config::ServerParams,
    core::{KMS, operations::CryptoOpSpec},
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

const EMPTY_SLICE: &[u8] = &[];

/// Marker type for the Encrypt operation's key selection requirements.
pub(crate) struct EncryptOp;

impl CryptoOpSpec for EncryptOp {
    type Request = Encrypt;
    type Response = EncryptResponse;

    const KMIP_OP: KmipOperation = KmipOperation::Encrypt;
    const OP_NAME: &'static str = "Encrypt";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        request.unique_identifier.as_ref()
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request.data.as_ref().map_or(0, |d| d.len())
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        if let Object::Certificate { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Encrypt, true);
        }
        if let Object::SymmetricKey { .. } | Object::PublicKey { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Encrypt, false);
        }
        if let Object::PGPKey { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Encrypt, false);
        }
        false
    }

    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        user: &UserId,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) => {
                KmsError::ItemNotFound(format!("Encrypt: key id: {unique_identifier}, not found"))
            }
            KmsError::Unauthorized(_) => KmsError::Unauthorized(format!(
                "Encrypt: the user {user} does not have permission to encrypt using the key: \
                 {unique_identifier}"
            )),
            other => other,
        }
    }

    fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        _user: &UserId,
    ) -> KResult<Self::Response> {
        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
        })?;
        BulkData::deserialize(data).map_or_else(
            |_| encrypt_single(owm, &kms.params, request, &kms.rng),
            |bulk_data| encrypt_bulk(owm, &kms.params, request, bulk_data, &kms.rng),
        )
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
        })?;
        let lock = kms.crypto_oracles.read().await;
        let crypto_oracle = lock.get(prefix).ok_or_else(|| {
            KmsError::InvalidRequest(format!("Encrypt: unknown crypto oracle prefix: {prefix}"))
        })?;
        let ca = request
            .cryptographic_parameters
            .as_ref()
            .and_then(|cp| CryptoAlgorithm::from_kmip(cp).transpose())
            .transpose()?;
        let encrypted_content = crypto_oracle
            .encrypt(
                uid,
                data,
                ca.clone(),
                request.authenticated_encryption_additional_data.as_deref(),
                request.i_v_counter_nonce.as_deref(),
            )
            .await?;
        debug!(
            "algorithm: {ca:?}, ciphertext length: {}",
            encrypted_content.ciphertext.len()
        );
        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            data: Some(encrypted_content.ciphertext),
            i_v_counter_nonce: encrypted_content.iv,
            correlation_value: request.correlation_value.clone(),
            authenticated_encryption_tag: encrypted_content.tag,
        })
    }
}

pub(crate) async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &UserId,
) -> KResult<EncryptResponse> {
    trace!(
        "uid={:?}, data_len={}",
        request.unique_identifier,
        request.data.as_ref().map_or(0, |d| d.len())
    );
    Box::pin(kms.perform_crypto_operation::<EncryptOp>(request, user)).await
}

/// Encrypt a single plaintext with the key
/// and return the corresponding ciphertext.
/// The key can be a symmetric key, a public key or a certificate.
/// # Arguments
///  * `owm` - the object with metadata of the key
///  * `request` - the encryption request
/// # Returns
/// * the encrypt response
fn encrypt_single(
    owm: &ObjectWithMetadata,
    server_params: &ServerParams,
    request: &Encrypt,
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    match owm.object() {
        Object::SymmetricKey { .. } => encrypt_with_symmetric_key(request, owm, rng),
        Object::PublicKey { .. } => encrypt_with_public_key(request, server_params, owm, rng),
        Object::PGPKey { .. } => pgp_ops::pgp_encrypt(owm, request, rng),
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => encrypt_with_certificate(request, server_params, owm.id(), certificate_value, rng),
        other => kms_bail!(KmsError::NotSupported(format!(
            "encrypt: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

/// Encrypt multiple plaintexts with the same key
/// and return the corresponding ciphertexts.
///
/// This is a hack where `request.data` is a serialized `BulkData` object.
/// The `BulkData` object is deserialized and each plaintext is encrypted.
/// The ciphertexts are concatenated and returned as a single `BulkData` object.
/// # Arguments
/// * `owm` - the object with metadata of the key
/// * `request` - the encrypt request
/// * `bulk_data` - the bulk data to encrypt
/// # Returns
/// * the encrypt response
// TODO: Covercrypt already has a bulk encryption method; maybe this should be merged here
pub(super) fn encrypt_bulk(
    owm: &ObjectWithMetadata,
    server_params: &ServerParams,
    request: &Encrypt,
    bulk_data: BulkData,
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    debug!("==> encrypting {} clear texts", bulk_data.len());
    let mut ciphertexts = Vec::with_capacity(bulk_data.len());

    match owm.object() {
        Object::SymmetricKey { .. } => {
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                let (key_bytes, cipher) = get_key_and_cipher(request, owm)?;
                let nonce = match request.i_v_counter_nonce.as_deref() {
                    Some(n) => Cow::Borrowed(n),
                    None => Cow::Owned(random_nonce(rng, cipher)?),
                };
                if cipher.nonce_size() > 0
                    && nonce.len() != cipher.nonce_size()
                    && !cipher.allows_variable_nonce()
                {
                    return Err(KmsError::InvalidRequest(format!(
                        "Encrypt: invalid IV/nonce length: expected {} bytes for {cipher:?}, \
                         got {}",
                        cipher.nonce_size(),
                        nonce.len()
                    )));
                }
                let padding_method = request
                    .cryptographic_parameters
                    .as_ref()
                    .and_then(|cp| cp.padding_method)
                    .unwrap_or(PaddingMethod::PKCS5);
                let (ciphertext, tag) = sym_encrypt(
                    cipher,
                    key_bytes,
                    &nonce,
                    aad,
                    &plaintext,
                    Some(padding_method),
                )?;
                // concatenate nonce || ciphertext || tag
                let mut nct = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
                nct.extend_from_slice(&nonce);
                nct.extend_from_slice(&ciphertext);
                nct.extend_from_slice(&tag);
                ciphertexts.push(Zeroizing::new(nct));
            }
        }
        Object::PublicKey { .. } => {
            let mut item_request = request_without_data(request);
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                item_request.data = Some(plaintext);
                let response = encrypt_with_public_key(&item_request, server_params, owm, rng)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => {
            let mut item_request = request_without_data(request);
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                item_request.data = Some(plaintext);
                let response = encrypt_with_certificate(
                    &item_request,
                    server_params,
                    owm.id(),
                    certificate_value,
                    rng,
                )?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "Encrypt bulk: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }

    debug!("<== encrypted {} ciphertexts", ciphertexts.len());
    let mut serialized = BulkData::new(ciphertexts).serialize()?;
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        // ciphertexts are not secret: move the buffer out instead of copying it
        data: Some(std::mem::take(&mut *serialized)),
        i_v_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
}

/// Copy of `request` without its (bulk) `data`, to be filled per item.
fn request_without_data(request: &Encrypt) -> Encrypt {
    Encrypt {
        unique_identifier: request.unique_identifier.clone(),
        cryptographic_parameters: request.cryptographic_parameters.clone(),
        data: None,
        i_v_counter_nonce: request.i_v_counter_nonce.clone(),
        correlation_value: request.correlation_value.clone(),
        init_indicator: request.init_indicator,
        final_indicator: request.final_indicator,
        authenticated_encryption_additional_data: request
            .authenticated_encryption_additional_data
            .clone(),
    }
}

fn encrypt_with_symmetric_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    trace!("entering. owm: {}", owm.attributes());

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
        return Err(KmsError::NotSupported(
            "FPE_FF1 encryption is not supported in FIPS mode".to_owned(),
        ));
    }

    #[cfg(feature = "non-fips")]
    if cryptographic_algorithm == CryptographicAlgorithm::FPE_FF1 {
        let plaintext = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
        })?;
        let ciphertext = encrypt_fpe(
            key_block.key_bytes_ref()?,
            plaintext,
            request.authenticated_encryption_additional_data.as_deref(),
            request.i_v_counter_nonce.as_deref(),
        )
        .map_err(|e| KmsError::CryptographicError(format!("FPE encrypt failed: {e}")))?;
        return Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            data: Some(ciphertext),
            i_v_counter_nonce: None,
            correlation_value: request.correlation_value.clone(),
            authenticated_encryption_tag: None,
        });
    }
    let (key_bytes, aead) = get_key_and_cipher(request, owm)?;
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    // ECB (nonce_size == 0) MUST NOT output or require a nonce; do not generate one.
    let nonce = if aead.nonce_size() == 0 {
        Cow::Borrowed(EMPTY_SLICE)
    } else {
        let n = match request.i_v_counter_nonce.as_deref() {
            Some(n) => Cow::Borrowed(n),
            None => Cow::Owned(random_nonce(rng, aead)?),
        };
        let expected = aead.nonce_size();
        if n.len() != expected && !aead.allows_variable_nonce() {
            return Err(KmsError::InvalidRequest(format!(
                "Encrypt: invalid IV/nonce length: expected {expected} bytes for {:?}, got {}",
                aead,
                n.len()
            )));
        }
        n
    };
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let padding_method = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.padding_method)
        .unwrap_or({
            // KMIP mandatory vectors for ECB expect no padding when the plaintext is block aligned
            // and omit an explicit PaddingMethod. Default to None ONLY for ECB; keep PKCS5 elsewhere.
            match aead {
                SymCipher::Aes128Ecb | SymCipher::Aes192Ecb | SymCipher::Aes256Ecb => {
                    PaddingMethod::None
                }
                _ => PaddingMethod::PKCS5,
            }
        });
    if aead.nonce_size() == 0 {
        trace!(
            "ECB encrypt: plaintext_len={}, padding_method={padding_method:?}",
            plaintext.len()
        );
    } else {
        trace!(
            "plaintext_len={}, nonce_len={}, aad_len={}, padding_method={padding_method:?}",
            plaintext.len(),
            nonce.len(),
            aad.len()
        );
    }
    let (ciphertext, tag) = sym_encrypt(
        aead,
        key_bytes,
        &nonce,
        aad,
        plaintext,
        Some(padding_method),
    )?;

    if aead.nonce_size() == 0 {
        trace!("ECB encrypt result: ciphertext_len={}", ciphertext.len());
    } else {
        trace!(
            "encrypt result: ciphertext_len={}, tag_len={}",
            ciphertext.len(),
            tag.len()
        );
    }
    // Validate and apply AEAD TagLength handling.
    // For AEAD (ChaCha20-Poly1305), KMIP vectors expect an invalid tag length to fail the request
    // (e.g., TagLength=1). For GCM, vectors accept only specific lengths; reject others.
    let adjusted_tag = if aead.tag_size() != 0 {
        if let Some(cp) = request.cryptographic_parameters.as_ref() {
            if let Some(mode) = cp.block_cipher_mode {
                match mode {
                    BlockCipherMode::AEAD => {
                        if let Some(tl) = cp.tag_length {
                            // ChaCha20-Poly1305 has a fixed 16-byte tag; reject mismatched lengths
                            let expected = tag.len();
                            if usize::try_from(tl).ok() != Some(expected) {
                                return Err(KmsError::Kmip21Error(
                                    ErrorReason::General_Failure,
                                    "L_KMIPCRYPTO_random:invalid-tag-length".to_owned(),
                                ));
                            }
                        }
                        Some(tag)
                    }
                    BlockCipherMode::GCM => {
                        if let Some(tl) = cp.tag_length {
                            // KMIP vectors validate GCM TagLength values; allow 12..=16 bytes only.
                            let tl_usize = usize::try_from(tl)?;
                            if !(12..=16).contains(&tl_usize) {
                                return Err(KmsError::Kmip21Error(
                                    ErrorReason::General_Failure,
                                    "L_KMIPCRYPTO_random:invalid-tag-length".to_owned(),
                                ));
                            }
                            // Truncate to requested length within allowed range
                            let truncated = if tl_usize < tag.len() {
                                tag.get(..tl_usize)
                                    .map_or_else(|| tag.clone(), std::borrow::ToOwned::to_owned)
                            } else {
                                tag
                            };
                            Some(truncated)
                        } else {
                            Some(tag)
                        }
                    }
                    _ => Some(tag),
                }
            } else {
                Some(tag)
            }
        } else {
            Some(tag)
        }
    } else {
        None
    };

    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(ciphertext),
        // nonce-return-policy:
        // The value used if the Cryptographic Parameters specified Random IV
        // and the IV/Counter/Nonce value was not provided in the request and the algorithm requires the provision of an IV/Counter/Nonce.
        i_v_counter_nonce: if aead.nonce_size() != 0
            && request
                .i_v_counter_nonce
                .as_ref()
                .map_or(0, std::vec::Vec::len)
                == 0
        {
            Some(nonce.into_owned())
        } else {
            None
        },
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: adjusted_tag,
    })
}

fn get_key_and_cipher<'a>(
    request: &Encrypt,
    owm: &'a ObjectWithMetadata,
) -> KResult<(&'a [u8], SymCipher)> {
    trace!("Entering get_key_and_cipher");
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes())
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ));
    }
    let key_block = owm.object().key_block()?;
    // Prevent FPE_FF1 keys from being misused for standard symmetric operations.
    // FPE_FF1 encryption is handled before this point; reaching here with an FPE_FF1
    // key means the caller explicitly requested a different algorithm, which is a misuse.
    if key_block.cryptographic_algorithm().copied() == Some(CryptographicAlgorithm::FPE_FF1) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "an FPE_FF1 key may only be used for FPE_FF1 encrypt operations".to_owned(),
        ));
    }
    let key_bytes = key_block.key_bytes_ref()?;
    let aead = match key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            // recover the cryptographic algorithm from the request or the key block or default to AES
            let req_cp = request.cryptographic_parameters.as_ref();
            let stored_cp = owm.attributes().cryptographic_parameters.as_ref();
            let cryptographic_algorithm = req_cp
                .and_then(|cp| cp.cryptographic_algorithm)
                .or_else(|| stored_cp.and_then(|cp| cp.cryptographic_algorithm))
                .or_else(|| key_block.cryptographic_algorithm().copied())
                .unwrap_or(CryptographicAlgorithm::AES);
            // Block cipher mode may be only on stored attributes (e.g. ECB). If absent in request, fallback to stored.
            let block_cipher_mode = req_cp
                .and_then(|cp| cp.block_cipher_mode)
                .or_else(|| stored_cp.and_then(|cp| cp.block_cipher_mode));
            SymCipher::from_algorithm_and_key_size(
                cryptographic_algorithm,
                block_cipher_mode,
                key_bytes.len(),
            )?
        }
        other => {
            return Err(KmsError::NotSupported(format!(
                "symmetric encryption with keys of format: {other}"
            )));
        }
    };
    Ok((key_bytes, aead))
}

fn encrypt_with_public_key(
    request: &Encrypt,
    server_params: &ServerParams,
    owm: &ObjectWithMetadata,
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes())
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ));
    }

    let key_block = owm.object().key_block()?;

    match &key_block.key_format_type {
        #[cfg(feature = "non-fips")]
        KeyFormatType::ConfigurableKEMPublicKey => {
            use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
                crypto::kem::{kem_encaps, kem_key_components},
                reexport::cosmian_crypto_core::bytes_ser_de::Serializable,
            };

            use crate::core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_kem_components;

            reject_kem_plaintext(request)?;
            let (ek_bytes, _) = owm.object().key_block()?.key_bytes_and_attributes()?;
            enforce_kmip_algorithm_policy_for_kem_components(
                server_params,
                "Encrypt",
                owm.id(),
                kem_key_components(&ek_bytes)?,
            )?;
            let (key, enc) = kem_encaps(&ek_bytes)?;
            // Published `ConfigurableKEM` contract: `Data` holds the serialized
            // `(shared secret, encapsulation)` tuple and `IVCounterNonce` is empty.
            // Do not align it with the ML-KEM layout.
            Ok(EncryptResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                data: Some(
                    (key, enc)
                        .serialize()
                        .map_err(|e| {
                            KmsError::ConversionError(format!(
                                "failed serializing the configurable-KEM encapsulation \
                                 results: {e}"
                            ))
                        })?
                        .to_vec(),
                ),
                i_v_counter_nonce: None,
                correlation_value: None,
                authenticated_encryption_tag: None,
            })
        }
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptPublicKey => {
            CoverCryptEncryption::instantiate(Covercrypt::default(), owm.id(), owm.object())?
                .encrypt(request)
                .map_err(Into::into)
        }
        KeyFormatType::TransparentECPublicKey
        | KeyFormatType::TransparentRSAPublicKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8
        | KeyFormatType::Raw => {
            // Check for KEM: if the key's algorithm is ML-KEM or hybrid KEM, perform encapsulation
            // instead of standard encryption.
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
                    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::ml_kem::ml_kem_encapsulate;
                    reject_kem_plaintext(request)?;
                    let (pub_bytes, _) = key_block.key_bytes_and_attributes()?;
                    let (shared_secret, ciphertext) = ml_kem_encapsulate(&pub_bytes)?;
                    return Ok(EncryptResponse {
                        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                        data: Some(shared_secret),
                        i_v_counter_nonce: Some(ciphertext),
                        correlation_value: request.correlation_value.clone(),
                        authenticated_encryption_tag: None,
                    });
                }
                if let Some(
                    algo @ (CryptographicAlgorithm::X25519MLKEM768
                    | CryptographicAlgorithm::X448MLKEM1024),
                ) = key_algo
                {
                    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::hybrid_kem::hybrid_kem_encapsulate;
                    reject_kem_plaintext(request)?;
                    let (pub_bytes, _) = key_block.key_bytes_and_attributes()?;
                    let (shared_secret, ciphertext) = hybrid_kem_encapsulate(algo, &pub_bytes)?;
                    return Ok(EncryptResponse {
                        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                        data: Some(shared_secret),
                        i_v_counter_nonce: Some(ciphertext),
                        correlation_value: request.correlation_value.clone(),
                        authenticated_encryption_tag: None,
                    });
                }
            }

            let plaintext = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
            })?;
            trace!(
                "matching on key format type: {:?}",
                key_block.key_format_type
            );
            let public_key = kmip_public_key_to_openssl(owm.object())?;
            trace!("OpenSSL Public Key instantiated before encryption");
            encrypt_with_pkey(
                request,
                server_params,
                owm.id(),
                owm.attributes(),
                plaintext,
                &public_key,
                rng,
            )
        }
        other => Err(KmsError::NotSupported(format!(
            "encryption with public keys of format: {other}"
        ))),
    }
}

/// A KEM encapsulation generates its own shared secret: refuse plaintext rather than
/// silently ignoring it.
#[cfg(feature = "non-fips")]
fn reject_kem_plaintext(request: &Encrypt) -> KResult<()> {
    if request.data.as_ref().is_some_and(|data| !data.is_empty()) {
        return Err(KmsError::InvalidRequest(
            "Encrypt: a KEM public key encapsulates a fresh shared secret; data to encrypt must \
             be empty"
                .to_owned(),
        ));
    }
    Ok(())
}

fn encrypt_with_pkey(
    request: &Encrypt,
    #[cfg(feature = "non-fips")] server_params: &ServerParams,
    #[cfg(not(feature = "non-fips"))] _server_params: &ServerParams,
    key_id: &str,
    #[cfg(feature = "non-fips")] key_attributes: &Attributes,
    #[cfg(not(feature = "non-fips"))] _key_attributes: &Attributes,
    plaintext: &[u8],
    public_key: &PKey<Public>,
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    let ciphertext = match public_key.id() {
        Id::RSA => {
            // Merge stored key cryptographic parameters (from key attributes if available via request? For encryption,
            // we only have the request parameters and the key's own attributes if we retrieved them earlier.
            // Here we do not have direct access to the key's Attributes (only key id + public key) so we rely solely
            // on request parameters for now. If future need arises we can thread Attributes through.
            encrypt_with_rsa(
                public_key,
                request.cryptographic_parameters.as_ref(),
                plaintext,
                rng,
            )?
        }
        #[cfg(feature = "non-fips")]
        Id::EC | Id::X25519 | Id::ED25519 => {
            enforce_ecies_fixed_suite_for_attributes(
                server_params,
                "Encrypt",
                key_id,
                key_attributes,
            )?;
            ecies_encrypt(rng, public_key, plaintext)?
        }
        other => {
            kms_bail!("Encrypt: public key type not supported: {other:?}")
        }
    };
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_owned()),
        data: Some(ciphertext),
        i_v_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_rsa(
    public_key: &PKey<Public>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    plaintext: &[u8],
    rng: &KmsRng,
) -> KResult<Vec<u8>> {
    let (algorithm, padding, hashing_fn, _) =
        default_cryptographic_parameters(cryptographic_parameters);
    let (mgf1_hash_fn, label) = cryptographic_parameters.map_or((hashing_fn, None), |cp| {
        (
            cp.mask_generator_hashing_algorithm.unwrap_or(hashing_fn),
            cp.p_source.as_deref(),
        )
    });
    debug!(
        "encrypting with RSA {algorithm:?} {padding:?} hashing_fn:{hashing_fn:?} mgf1:{mgf1_hash_fn:?} label_len:{}",
        label.map_or(0, <[u8]>::len)
    );

    let ciphertext = match algorithm {
        CryptographicAlgorithm::RSA => match padding {
            PaddingMethod::None => ckm_rsa_aes_key_wrap(rng, public_key, hashing_fn, plaintext)?,
            PaddingMethod::OAEP => {
                ckm_rsa_pkcs_oaep_encrypt(public_key, hashing_fn, mgf1_hash_fn, label, plaintext)?
            }
            #[cfg(feature = "non-fips")]
            PaddingMethod::PKCS1v15 => ckm_rsa_pkcs_encrypt(public_key, plaintext)?,
            _ => kms_bail!("Unable to encrypt with RSA: padding method not supported: {padding:?}"),
        },
        x => {
            kms_bail!("Unable to encrypt with RSA: algorithm not supported for encrypting: {x:?}")
        }
    };
    Ok(ciphertext)
}

fn encrypt_with_certificate(
    request: &Encrypt,
    server_params: &ServerParams,
    key_id: &str,
    certificate_value: &[u8],
    rng: &KmsRng,
) -> KResult<EncryptResponse> {
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let cert = X509::from_der(certificate_value)
        .map_err(|e| KmipError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
    let public_key = cert.public_key().map_err(|e| {
        KmipError::ConversionError(format!("invalid certificate public key: error: {e:?}"))
    })?;
    // No key `Attributes` are available when encrypting with a raw certificate.
    // If the certificate key is an ECIES-capable key type, fall back to strict PKey-id enforcement.
    #[cfg(feature = "non-fips")]
    {
        match public_key.id() {
            Id::EC | Id::X25519 | Id::ED25519 => {
                enforce_ecies_fixed_suite_for_pkey_id(
                    server_params,
                    "Encrypt",
                    key_id,
                    public_key.id(),
                )?;
            }
            _ => {}
        }
    }
    encrypt_with_pkey(
        request,
        server_params,
        key_id,
        &Attributes::default(),
        plaintext,
        &public_key,
        rng,
    )
}

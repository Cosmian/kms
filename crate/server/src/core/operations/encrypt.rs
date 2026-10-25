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
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, PaddingMethod},
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
            symmetric::symmetric_ciphers::{
                Mode, StreamCipher, SymCipher, encrypt as sym_encrypt, random_nonce,
            },
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
    core::{
        KMS,
        operations::{
            CryptoOpSpec,
            key_ops::multi_part::{FixedFields, Part, StreamOwner, reject_multi_part_for_oracle},
        },
    },
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
        user: &UserId,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        if part.is_multi_part() {
            return encrypt_multi_part(kms, owm, request, part, user);
        }
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
        reject_multi_part_for_oracle(
            Self::OP_NAME,
            Part::classify(
                request.init_indicator,
                request.final_indicator,
                request.correlation_value.as_deref(),
            )?,
        )?;
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
            // One IV for several items would reuse a nonce under the same key (fatal for GCM):
            // every item then gets a fresh random nonce, prepended to its ciphertext.
            if request.i_v_counter_nonce.is_some() && bulk_data.len() > 1 {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Invalid_Field,
                    "Encrypt: an IV/Counter/Nonce cannot be supplied for bulk encryption of \
                     several items"
                        .to_owned(),
                ));
            }
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
    trace!("Encrypting with symmetric key");

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
    let (nonce, generated_nonce) = encryption_nonce(request, stored_cp, aead, rng)?;
    let tag_length = tag_length(request.cryptographic_parameters.as_ref(), aead)?;
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let padding_method = padding_method(request.cryptographic_parameters.as_ref(), aead);
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
    let adjusted_tag = (aead.tag_size() != 0).then(|| truncate_tag(tag, tag_length));

    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(ciphertext),
        // KMIP 2.1 Table 215: the IV is returned only when the server generated it.
        i_v_counter_nonce: generated_nonce.then(|| nonce.into_owned()),
        correlation_value: None,
        authenticated_encryption_tag: adjusted_tag,
    })
}

/// Cryptographic Parameters field from the request, else from the key's stored attributes.
fn parameter<T>(
    request: Option<&CryptographicParameters>,
    stored: Option<&CryptographicParameters>,
    field: impl Fn(&CryptographicParameters) -> Option<T>,
) -> Option<T> {
    request.and_then(&field).or_else(|| stored.and_then(&field))
}

/// IV/Counter/Nonce of a symmetric encryption (KMIP 2.1 §6.1.17): the request's value, or a
/// server-generated random one (returned in the response, flagged by the returned boolean).
///
/// Honours `IV Length` and `Random IV`; deterministic IV construction (`Fixed Field Length`,
/// `Invocation Field Length`) and counter settings (`Counter Length`, `Initial Counter Value`)
/// are not implemented and are rejected as unsupported.
pub(super) fn encryption_nonce<'a>(
    request: &'a Encrypt,
    stored: Option<&CryptographicParameters>,
    cipher: SymCipher,
    rng: &KmsRng,
) -> KResult<(Cow<'a, [u8]>, bool)> {
    if cipher.nonce_size() == 0 {
        return Ok((Cow::Borrowed(EMPTY_SLICE), false));
    }
    let req_cp = request.cryptographic_parameters.as_ref();
    for cp in [req_cp, stored].into_iter().flatten() {
        if cp.fixed_field_length.is_some()
            || cp.invocation_field_length.is_some()
            || cp.counter_length.is_some()
            || cp.initial_counter_value.is_some()
        {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                "Encrypt: Fixed Field Length, Invocation Field Length, Counter Length and \
                 Initial Counter Value are not supported"
                    .to_owned(),
            ));
        }
    }
    // `IV Length` is in bits: a multiple of 8, at most 1024 (OpenSSL's 128-byte IV limit),
    // validated before anything is allocated.
    let invalid_iv_length = |bits: i32| {
        KmsError::Kmip21Error(
            ErrorReason::Bad_Cryptographic_Parameters,
            format!("Encrypt: IV Length of {bits} bits is not valid for {cipher:?}"),
        )
    };
    // A client-supplied IV is used as is: IV Length only sizes a server-generated IV, and
    // deployed clients send it in bytes, so an unusable value is not an error in that case.
    let iv_supplied = request
        .i_v_counter_nonce
        .as_deref()
        .is_some_and(|iv| !iv.is_empty());
    let iv_length = if iv_supplied {
        None
    } else {
        parameter(req_cp, stored, |cp| cp.iv_length)
            .map(|bits| {
                usize::try_from(bits)
                    .ok()
                    .filter(|b| (8..=1024).contains(b) && b % 8 == 0)
                    .map(|b| b / 8)
                    .filter(|len| *len == cipher.nonce_size() || cipher.allows_variable_nonce())
                    .or_else(|| {
                        // Legacy clients send the length in bytes.
                        usize::try_from(bits)
                            .ok()
                            .filter(|b| *b == cipher.nonce_size())
                    })
                    .ok_or_else(|| invalid_iv_length(bits))
            })
            .transpose()?
    };
    match request.i_v_counter_nonce.as_deref() {
        Some(iv) if !iv.is_empty() => {
            let expected = cipher.nonce_size();
            if iv.len() != expected && !cipher.allows_variable_nonce() {
                return Err(KmsError::InvalidRequest(format!(
                    "Encrypt: invalid IV/nonce length: expected {expected} bytes for {cipher:?}, \
                     got {}",
                    iv.len()
                )));
            }
            Ok((Cow::Borrowed(iv), false))
        }
        // Random IV explicitly disabled and no IV supplied
        _ if parameter(req_cp, stored, |cp| cp.random_iv) == Some(false) => {
            Err(KmsError::Kmip21Error(
                ErrorReason::Missing_Initialization_Vector,
                "missing-iv".to_owned(),
            ))
        }
        _ => {
            let len = iv_length.unwrap_or_else(|| cipher.nonce_size());
            // A server-generated random GCM IV is at least 96 bits (NIST SP 800-38D §8.2.2).
            if cipher.allows_variable_nonce() && len < 12 {
                return Err(invalid_iv_length(
                    parameter(req_cp, stored, |cp| cp.iv_length).unwrap_or_default(),
                ));
            }
            let mut nonce = vec![0; len];
            rng.fill_bytes(&mut nonce)?;
            Ok((Cow::Owned(nonce), true))
        }
    }
}

fn invalid_tag_length() -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Bad_Cryptographic_Parameters,
        "L_KMIPCRYPTO_random:invalid-tag-length".to_owned(),
    )
}

/// Validated `Tag Length` (bytes) requested for an authenticated encryption, `None` for the
/// cipher's full tag. GCM and ChaCha20-Poly1305 accept 12 to 16 bytes (truncation, see
/// [`SymCipher::min_tag_size`]); other AEAD ciphers only their full tag length.
pub(super) fn tag_length(
    cp: Option<&CryptographicParameters>,
    cipher: SymCipher,
) -> KResult<Option<usize>> {
    let Some(requested) = cp.and_then(|cp| cp.tag_length) else {
        return Ok(None);
    };
    if cipher.tag_size() == 0 {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Unsupported_Cryptographic_Parameters,
            "TagLength is only supported for authenticated encryption modes".to_owned(),
        ));
    }
    let requested = usize::try_from(requested).map_err(|_e| invalid_tag_length())?;
    if !(cipher.min_tag_size()..=cipher.tag_size()).contains(&requested) {
        return Err(invalid_tag_length());
    }
    Ok(Some(requested))
}

fn truncate_tag(mut tag: Vec<u8>, tag_length: Option<usize>) -> Vec<u8> {
    if let Some(len) = tag_length {
        tag.truncate(len);
    }
    tag
}

/// Ciphers whose OpenSSL streaming matches their one-shot output, hence usable for multi-part
/// operations. XTS (one data unit per call), key wrapping, GCM-SIV and the custom `ChaCha20`
/// nonce layout are single-part only (KMIP 2.1 §6.1: multi-part support is optional).
pub(super) fn ensure_multi_part_cipher(op: &str, cipher: SymCipher) -> KResult<()> {
    let supported = match cipher {
        SymCipher::Aes128Ecb
        | SymCipher::Aes192Ecb
        | SymCipher::Aes256Ecb
        | SymCipher::Aes128Cbc
        | SymCipher::Aes192Cbc
        | SymCipher::Aes256Cbc
        | SymCipher::Aes128Gcm
        | SymCipher::Aes192Gcm
        | SymCipher::Aes256Gcm => true,
        #[cfg(feature = "non-fips")]
        SymCipher::Chacha20Poly1305 => true,
        _ => false,
    };
    if !supported {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            format!("{op}: multi-part operations are not supported with {cipher:?}"),
        ));
    }
    Ok(())
}

/// Default padding: none for ECB (KMIP mandatory vectors), PKCS#5 otherwise.
pub(super) fn padding_method(
    cp: Option<&CryptographicParameters>,
    cipher: SymCipher,
) -> PaddingMethod {
    cp.and_then(|cp| cp.padding_method).unwrap_or(match cipher {
        SymCipher::Aes128Ecb | SymCipher::Aes192Ecb | SymCipher::Aes256Ecb => PaddingMethod::None,
        _ => PaddingMethod::PKCS5,
    })
}

/// Whether OpenSSL must pad (ECB/CBC only); other padding methods are unsupported.
pub(super) fn openssl_padding(padding: PaddingMethod) -> KResult<bool> {
    match padding {
        PaddingMethod::None => Ok(false),
        PaddingMethod::PKCS5 => Ok(true),
        other => Err(KmsError::Kmip21Error(
            ErrorReason::Unsupported_Cryptographic_Parameters,
            format!("Padding method {other:?} is not currently supported"),
        )),
    }
}

/// State of a multi-part encryption.
struct EncryptState {
    cipher: StreamCipher,
    tag_length: Option<usize>,
    nonce_to_return: Option<Vec<u8>>,
    fixed: FixedFields,
}

/// Multi-part symmetric encryption (KMIP 2.1 §6.1 and §6.1.17): the OpenSSL cipher context
/// is kept server-side under the Correlation Value; the tag is returned with the final part.
fn encrypt_multi_part(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    request: &Encrypt,
    part: Part<'_>,
    user: &UserId,
) -> KResult<EncryptResponse> {
    let owner = StreamOwner {
        op: EncryptOp::OP_NAME,
        user,
        key_uid: owm.id(),
    };
    let ((data, nonce, tag), correlation_value) = kms.multi_part.run(
        &kms.rng,
        part,
        owner,
        || {
            if !matches!(owm.object(), Object::SymmetricKey { .. }) {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Feature_Not_Supported,
                    "Encrypt: multi-part encryption is only supported with symmetric keys"
                        .to_owned(),
                ));
            }
            let (key_bytes, cipher) = get_key_and_cipher(request, owm)?;
            ensure_multi_part_cipher(EncryptOp::OP_NAME, cipher)?;
            let stored_cp = owm.attributes().cryptographic_parameters.as_ref();
            let (nonce, generated) = encryption_nonce(request, stored_cp, cipher, &kms.rng)?;
            let tag_length = tag_length(request.cryptographic_parameters.as_ref(), cipher)?;
            let padding = openssl_padding(padding_method(
                request.cryptographic_parameters.as_ref(),
                cipher,
            ))?;
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            let mut stream = cipher.stream_cipher(Mode::Encrypt, key_bytes, &nonce, aad)?;
            stream.set_padding(padding);
            Ok(EncryptState {
                cipher: stream,
                tag_length,
                fixed: FixedFields::new(request.cryptographic_parameters.as_ref(), &nonce, aad),
                nonce_to_return: generated.then(|| nonce.into_owned()),
            })
        },
        |state, last| {
            state.fixed.check(
                EncryptOp::OP_NAME,
                request.cryptographic_parameters.as_ref(),
                request.i_v_counter_nonce.as_deref(),
                request.authenticated_encryption_additional_data.as_deref(),
            )?;
            let mut output = state.cipher.update(
                request
                    .data
                    .as_deref()
                    .map_or(EMPTY_SLICE, |d| d.as_slice()),
            )?;
            let tag = if last {
                let (tail, tag) = state.cipher.finalize_encryption()?;
                output.extend_from_slice(&tail);
                (!tag.is_empty()).then(|| truncate_tag(tag, state.tag_length))
            } else {
                None
            };
            Ok((output, state.nonce_to_return.take(), tag))
        },
    )?;
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: (!data.is_empty()).then_some(data),
        i_v_counter_nonce: nonce,
        correlation_value,
        authenticated_encryption_tag: tag,
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
            use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::kem::{
                kem_encaps, kem_key_components,
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
            kem_encrypt_response(owm.id(), request, key, enc)
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
                    return kem_encrypt_response(
                        owm.id(),
                        request,
                        Zeroizing::new(shared_secret),
                        Zeroizing::new(ciphertext),
                    );
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
                    return kem_encrypt_response(
                        owm.id(),
                        request,
                        Zeroizing::new(shared_secret),
                        Zeroizing::new(ciphertext),
                    );
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

/// The `Encrypt` response of every KEM public key: the shared secret and the encapsulation
/// packed as a serialized tuple in `Data`. The encapsulation is a ciphertext, so it must not
/// travel in `IVCounterNonce`, which carries public cipher metadata (an IV/counter/nonce).
#[cfg(feature = "non-fips")]
fn kem_encrypt_response(
    uid: &str,
    request: &Encrypt,
    shared_secret: Zeroizing<Vec<u8>>,
    encapsulation: Zeroizing<Vec<u8>>,
) -> KResult<EncryptResponse> {
    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::kem::pack_kem_encapsulation;

    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        data: Some(pack_kem_encapsulation(shared_secret, encapsulation)?.to_vec()),
        i_v_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
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

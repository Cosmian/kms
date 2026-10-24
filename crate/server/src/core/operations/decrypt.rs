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
            symmetric::symmetric_ciphers::{Mode, StreamCipher, SymCipher, decrypt as sym_decrypt},
        },
        openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::{CryptoAlgorithm, ObjectWithMetadata},
};
use cosmian_logger::{debug, trace};
use openssl::pkey::{Id, PKey, Private};
use zeroize::Zeroizing;

use super::{
    encrypt::{ensure_multi_part_cipher, openssl_padding, padding_method, tag_length},
    pgp_ops,
};
#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::enforce_ecies_fixed_suite_for_attributes;
use crate::{
    config::ServerParams,
    core::{
        KMS,
        operations::{
            CryptoOpSpec, KeysetMode,
            key_ops::multi_part::{FixedFields, Part, StreamOwner, reject_multi_part_for_oracle},
        },
    },
    error::KmsError,
    middlewares::UserId,
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
            return owm.has_usage_mask(CryptographicUsageMask::Decrypt, false);
        }
        if let Object::PGPKey { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Decrypt, false);
        }
        if let Object::PrivateKey { .. } = owm.object() {
            if !owm.has_usage_mask(CryptographicUsageMask::Decrypt, false) {
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
        user: &UserId,
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
            return decrypt_multi_part(kms, owm, request, part, user);
        }
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
        reject_multi_part_for_oracle(
            Self::OP_NAME,
            Part::classify(
                request.init_indicator,
                request.final_indicator,
                request.correlation_value.as_deref(),
            )?,
        )?;
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
    user: &UserId,
) -> KResult<DecryptResponse> {
    trace!(
        "Decrypt: uid={:?}, data_len={}",
        request.unique_identifier,
        request.data.as_ref().map_or(0, Vec::len)
    );
    Box::pin(kms.perform_crypto_operation::<DecryptOp>(request, user)).await
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
            // Clone the request once, then only swap the `data` field per ciphertext
            // to avoid cloning the whole Decrypt request on every iteration.
            let mut request = request.clone();
            for mut ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(std::mem::take(&mut *ciphertext));
                let response = decrypt_with_covercrypt(owm, &request)?;
                plaintexts.push(response.data.unwrap_or_default());
            }
        }

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            // Clone the request once, then only swap the `data` field per ciphertext
            // to avoid cloning the whole Decrypt request on every iteration.
            let mut request = request.clone();
            for mut ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(std::mem::take(&mut *ciphertext));
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
                    key_bytes,
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
    if let Object::PGPKey { .. } = owm.object() {
        return pgp_ops::pgp_decrypt(owm, request);
    }
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
            key_block.key_bytes_ref()?,
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
    let nonce_storage = decryption_nonce(request.i_v_counter_nonce.as_deref(), aead)?;
    let nonce: &[u8] = nonce_storage.as_ref();
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let tag = if aead.tag_size() == 0 {
        EMPTY_SLICE
    } else {
        let tag = request
            .authenticated_encryption_tag
            .as_deref()
            .unwrap_or(EMPTY_SLICE);
        check_decryption_tag(request.cryptographic_parameters.as_ref(), aead, tag)?;
        tag
    };
    let padding_method = padding_method(request.cryptographic_parameters.as_ref(), aead);
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
        key_bytes,
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

/// IV/Counter/Nonce of a symmetric decryption (KMIP 2.1 §6.1.11):
/// - not used by the cipher (ECB)  → none;
/// - absent                        → `Missing Initialization Vector` (message `missing-iv`);
/// - present but empty             → all-zero IV (some clients send this to request a zero IV);
/// - correct length, or any for GCM → used as-is (OpenSSL derives J0 for non-96-bit IVs);
/// - wrong length                  → `Invalid Field` (message `invalid-iv-length`).
fn decryption_nonce(provided: Option<&[u8]>, cipher: SymCipher) -> KResult<Cow<'_, [u8]>> {
    if cipher.nonce_size() == 0 {
        return Ok(Cow::Borrowed(EMPTY_SLICE));
    }
    match provided {
        None => Err(KmsError::Kmip21Error(
            ErrorReason::Missing_Initialization_Vector,
            "missing-iv".to_owned(),
        )),
        Some([]) => Ok(Cow::Owned(vec![0_u8; cipher.nonce_size()])),
        Some(iv) if iv.len() == cipher.nonce_size() || cipher.allows_variable_nonce() => {
            Ok(Cow::Borrowed(iv))
        }
        Some(iv) => Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!(
                "invalid-iv-length: expected {} got {}",
                cipher.nonce_size(),
                iv.len()
            ),
        )),
    }
}

/// Authenticated Encryption Tag of an AEAD decryption (KMIP 2.1 §6.1.11, Table 198).
///
/// A declared `Tag Length` must be valid for the cipher (`Bad Cryptographic Parameters`) and
/// equal the supplied tag's length; a supplied tag must be `min_tag_size()..=tag_size()` bytes
/// (12 to 16 for GCM): shorter tags make forgeries cheap (`Invalid Field`). A missing tag is
/// left to the cipher, which fails with `Cryptographic Failure`.
fn check_decryption_tag(
    cp: Option<&CryptographicParameters>,
    cipher: SymCipher,
    tag: &[u8],
) -> KResult<()> {
    let declared = tag_length(cp, cipher)?;
    if !tag.is_empty()
        && (declared.is_some_and(|len| len != tag.len())
            || cipher.check_tag_length(tag.len()).is_err())
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!(
                "Decrypt: invalid Authenticated Encryption Tag length {} for {cipher:?} \
                 (declared Tag Length: {declared:?})",
                tag.len()
            ),
        ));
    }
    Ok(())
}

/// State of a multi-part decryption; the tag may come with the initial or the final part.
struct DecryptState {
    stream: StreamCipher,
    cipher: SymCipher,
    fixed: FixedFields,
    tag: Option<Vec<u8>>,
}

/// Multi-part symmetric decryption (KMIP 2.1 §6.1 and §6.1.11): the OpenSSL cipher context is
/// kept server-side under the Correlation Value; the tag is checked by the final part.
///
/// **Unauthenticated plaintext.** Every part returns the plaintext of its ciphertext at once,
/// as the KMIP mandatory profile requires (OASIS `CS-BC-M-GCM-3-21` expects plaintext in the
/// initial response). For AEAD ciphers (GCM, ChaCha20-Poly1305) that plaintext is therefore
/// released *before* the tag is verified: it is unauthenticated, and may have been tampered
/// with, until the final part succeeds. Clients must discard everything received when the final
/// part fails, or use single-part Decrypt, which verifies the tag before returning anything.
/// Any failure (including a wrong tag) drops the stream, so a failed operation cannot go on.
fn decrypt_multi_part(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    request: &Decrypt,
    part: Part<'_>,
    user: &UserId,
) -> KResult<DecryptResponse> {
    let owner = StreamOwner {
        op: DecryptOp::OP_NAME,
        user,
        key_uid: owm.id(),
    };
    let (data, correlation_value) = kms.multi_part.run(
        &kms.rng,
        part,
        owner,
        || {
            if !matches!(owm.object(), Object::SymmetricKey { .. }) {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Feature_Not_Supported,
                    "Decrypt: multi-part decryption is only supported with symmetric keys"
                        .to_owned(),
                ));
            }
            let (key_bytes, cipher) = get_aead_and_key(owm, request)?;
            ensure_multi_part_cipher(DecryptOp::OP_NAME, cipher)?;
            let nonce = decryption_nonce(request.i_v_counter_nonce.as_deref(), cipher)?;
            let padding = openssl_padding(padding_method(
                request.cryptographic_parameters.as_ref(),
                cipher,
            ))?;
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            let mut stream = cipher.stream_cipher(Mode::Decrypt, key_bytes, &nonce, aad)?;
            stream.set_padding(padding);
            Ok(DecryptState {
                stream,
                cipher,
                fixed: FixedFields::new(request.cryptographic_parameters.as_ref(), &nonce, aad),
                tag: None,
            })
        },
        |state, last| {
            state.fixed.check(
                DecryptOp::OP_NAME,
                request.cryptographic_parameters.as_ref(),
                request.i_v_counter_nonce.as_deref(),
                request.authenticated_encryption_additional_data.as_deref(),
            )?;
            if let Some(tag) = &request.authenticated_encryption_tag {
                if state.cipher.tag_size() > 0 {
                    check_decryption_tag(
                        state.fixed.cryptographic_parameters(),
                        state.cipher,
                        tag,
                    )?;
                }
                state.tag = Some(tag.clone());
            }
            let mut output = Zeroizing::new(
                state
                    .stream
                    .update(request.data.as_deref().unwrap_or_default())?,
            );
            if last {
                let tag = if state.cipher.tag_size() == 0 {
                    EMPTY_SLICE
                } else {
                    state.tag.as_deref().ok_or_else(|| {
                        KmsError::Kmip21Error(
                            ErrorReason::Invalid_Field,
                            "Decrypt: the Authenticated Encryption Tag is required".to_owned(),
                        )
                    })?
                };
                let tail = Zeroizing::new(state.stream.finalize_decryption(tag)?);
                output.extend_from_slice(&tail);
            }
            Ok(output)
        },
    )?;
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: (!data.is_empty()).then_some(data),
        correlation_value,
    })
}

fn get_aead_and_key<'a>(
    owm: &'a ObjectWithMetadata,
    request: &Decrypt,
) -> Result<(&'a [u8], SymCipher), KmsError> {
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
    let key_bytes = key_block.key_bytes_ref()?;
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
            return Err(KmsError::Kmip21Error(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                format!("Decrypt with PKey: private key type not supported: {other:?}"),
            ));
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
        _ => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                "Decrypt: algorithm or padding method not supported for RSA decryption".to_owned(),
            ));
        }
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, ErrorReason},
        kmip_2_1::{
            extra::{
                BulkData,
                tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            },
            kmip_operations::{Decrypt, Encrypt},
            kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
            requests::symmetric_key_create_request,
        },
    };
    use zeroize::Zeroizing;

    use crate::{
        config::ServerParams, core::KMS, error::KmsError, middlewares::UserId, result::KResult,
        tests::test_utils::https_clap_config,
    };

    fn reason<T: std::fmt::Debug>(r: KResult<T>) -> Option<ErrorReason> {
        match r.unwrap_err() {
            KmsError::Kmip21Error(reason, _) => Some(reason),
            _ => None,
        }
    }

    fn gcm(tag_length: Option<i32>, iv_length: Option<i32>) -> CryptographicParameters {
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            tag_length,
            iv_length,
            ..CryptographicParameters::default()
        }
    }

    fn decrypt(
        uid: &UniqueIdentifier,
        data: &[u8],
        iv: &[u8],
        tag: Option<&[u8]>,
        tag_length: Option<i32>,
    ) -> Decrypt {
        Decrypt {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: Some(gcm(tag_length, None)),
            data: Some(data.to_vec()),
            i_v_counter_nonce: Some(iv.to_vec()),
            authenticated_encryption_tag: tag.map(<[u8]>::to_vec),
            ..Decrypt::default()
        }
    }

    #[tokio::test]
    async fn test_aead_tag_and_iv_hardening() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::from(ServerParams::try_from(https_clap_config())?)).await?,
        );
        let user = UserId::from("user");
        let create = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let uid = kms.create(create, &user).await?.unique_identifier;
        let encrypt = |data: Vec<u8>, iv: Option<Vec<u8>>, iv_length: Option<i32>| Encrypt {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: Some(gcm(None, iv_length)),
            data: Some(Zeroizing::new(data)),
            i_v_counter_nonce: iv,
            ..Encrypt::default()
        };

        let enc = kms
            .encrypt(encrypt(b"message".to_vec(), None, None), &user)
            .await?;
        let (ct, iv, tag) = (
            enc.data.unwrap(),
            enc.i_v_counter_nonce.unwrap(),
            enc.authenticated_encryption_tag.unwrap(),
        );

        // F1: truncated tags below 96 bits are refused, single-part and multi-part.
        for len in [1, 4, 8, 11] {
            let (short, _) = tag.split_at(len);
            let r = kms
                .decrypt(decrypt(&uid, &ct, &iv, Some(short), None), &user)
                .await;
            assert_eq!(reason(r), Some(ErrorReason::Invalid_Field), "{len}");
            let init = Decrypt {
                init_indicator: Some(true),
                ..decrypt(&uid, &ct, &iv, Some(short), None)
            };
            assert_eq!(
                reason(kms.decrypt(init, &user).await),
                Some(ErrorReason::Invalid_Field)
            );
        }
        // A 12-byte tag matching the declared Tag Length is accepted, a mismatch is not.
        let (tag12, _) = tag.split_at(12);
        let ok = kms
            .decrypt(decrypt(&uid, &ct, &iv, Some(tag12), Some(12)), &user)
            .await?;
        assert_eq!(ok.data.unwrap().as_slice(), b"message");
        let r = kms
            .decrypt(decrypt(&uid, &ct, &iv, Some(tag12), Some(16)), &user)
            .await;
        assert_eq!(reason(r), Some(ErrorReason::Invalid_Field));

        // F8: a later part cannot change the AAD; the failure aborts the stream.
        let init = Decrypt {
            init_indicator: Some(true),
            ..decrypt(&uid, &ct, &iv, Some(&tag), None)
        };
        let cv = kms.decrypt(init, &user).await?.correlation_value.unwrap();
        let next = |aad: Option<Vec<u8>>| Decrypt {
            unique_identifier: Some(uid.clone()),
            correlation_value: Some(cv.clone()),
            authenticated_encryption_additional_data: aad,
            final_indicator: Some(true),
            ..Decrypt::default()
        };
        let r = kms.decrypt(next(Some(b"other".to_vec())), &user).await;
        assert_eq!(reason(r), Some(ErrorReason::Invalid_Field));
        let r = kms.decrypt(next(None), &user).await;
        assert_eq!(reason(r), Some(ErrorReason::Invalid_Correlation_Value));

        // F4: one supplied IV is never reused across bulk items.
        let bulk = BulkData::from(vec![b"a".to_vec(), b"b".to_vec()])
            .serialize()?
            .to_vec();
        let r = kms
            .encrypt(encrypt(bulk, Some(vec![0; 12]), None), &user)
            .await;
        assert_eq!(reason(r), Some(ErrorReason::Invalid_Field));

        // F5: IV Length is bounded before allocation; generated GCM IVs are >= 96 bits.
        for bits in [i32::MAX - 7, 1032, 64] {
            let r = kms
                .encrypt(encrypt(b"m".to_vec(), None, Some(bits)), &user)
                .await;
            assert_eq!(
                reason(r),
                Some(ErrorReason::Bad_Cryptographic_Parameters),
                "{bits}"
            );
        }
        let enc = kms
            .encrypt(encrypt(b"m".to_vec(), None, Some(128)), &user)
            .await?;
        assert_eq!(enc.i_v_counter_nonce.unwrap().len(), 16);
        Ok(())
    }
}

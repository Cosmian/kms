#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::EncryptionSystem;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::ecies::ecies_encrypt;
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
        kmip_0::kmip_types::{
            BlockCipherMode, CryptographicUsageMask, ErrorReason, PaddingMethod, State,
        },
        kmip_2_1::{
            KmipOperation,
            extra::BulkData,
            kmip_objects::{Certificate, Object},
            kmip_operations::{Encrypt, EncryptResponse},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
                UsageLimitsUnit,
            },
        },
        time_normalize,
    },
    cosmian_kms_crypto::{
        crypto::{
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
use cosmian_logger::{debug, info, trace};
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::enforce_ecies_fixed_suite_for_pkey_id;
use crate::{
    config::ServerParams,
    core::{
        KMS,
        operations::{
            algorithm_policy::enforce_kmip_algorithm_policy_for_retrieved_key, get_effective_state,
        },
        uid_utils::{has_prefix, uids_from_unique_identifier},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn encrypt(kms: &KMS, request: Encrypt, user: &str) -> KResult<EncryptResponse> {
    trace!("{request}");

    // We do not (yet) support continuation cases
    let data = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms)
        .await
        .context("Encrypt")?;
    trace!("candidate uids: {uids:?}");

    // Determine which UID to select. The decision process is as follows: loop through the uids
    // 1. If the UID has a prefix, try using that
    // 2. If the UID does not have a prefix, fetch the corresponding object and check that
    //   a- the object is active
    //   b- the object is a public Key, a Symmetric Key, or a Certificate
    //
    // Permissions checks are done AFTER the object is fetched in the default database
    // to avoid calling `database.is_object_owned_by()` and hence a double call to the DB
    // for each uid. This is also based on the high probability that there is still a single object
    // in the candidate list.

    let mut selected_owm = None;
    for uid in uids {
        if let Some(prefix) = has_prefix(&uid) {
            if !kms.database.is_object_owned_by(&uid, user).await? {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false)
                    .await?;
                if !ops
                    .iter()
                    .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
                {
                    continue;
                }
            }
            debug!("user: {user} is authorized to encrypt using: {uid} from decryption oracle");
            return encrypt_using_encryption_oracle(kms, &request, data, &uid, prefix).await;
        }
        let owm = kms.database.retrieve_object(&uid).await?.ok_or_else(|| {
            KmsError::InvalidRequest(format!("Encrypt: failed to retrieve key: {uid}"))
        })?;
        // Check effective state (PreActive with past activation_date counts as Active)
        if get_effective_state(&owm)? != State::Active {
            continue;
        }
        // check user permissions - owner can always encrypt
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(&uid, user, false)
                .await?;
            if !ops
                .iter()
                .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
            {
                continue;
            }
        }
        trace!("user: {user} is authorized to encrypt using: {uid}");
        // TODO check why usage masks are not checked for certificates
        if let Object::Certificate { .. } = owm.object() {
            selected_owm = Some(owm);
            break;
        }
        if let Object::SymmetricKey { .. } | Object::PublicKey { .. } = owm.object() {
            // If an HSM wraps the object, likely the wrapping will be done with NoEncoding
            // and the attributes of the object will be empty. Use the metadata attributes.
            let attributes = owm
                .object()
                .attributes()
                .unwrap_or_else(|_| owm.attributes());
            trace!("attributes: {attributes}");
            if !attributes.is_usage_authorized_for(CryptographicUsageMask::Encrypt)? {
                continue;
            }
            selected_owm = Some(owm);
            break;
        }
    }
    let mut owm = selected_owm.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!("Encrypt: no valid key for id: {unique_identifier}"),
        )
    })?;

    // Enforce time window constraints: Active key is unusable for Encrypt if current time is
    // before ProcessStartDate OR after ProtectStopDate (when those attributes are present).
    // The CS-BC-M-14-21 vector sets ActivationDate in the past, ProcessStartDate in the future
    // and ProtectStopDate in the past expecting Encrypt to fail with WrongKeyLifecycleState.
    if get_effective_state(&owm)? == State::Active {
        if let Ok(attrs) = owm.object().attributes() {
            let now = time_normalize()?;
            let too_early = attrs.process_start_date.is_some_and(|d| now < d);
            let too_late = attrs.protect_stop_date.is_some_and(|d| now > d);
            if too_early || too_late {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Wrong_Key_Lifecycle_State,
                    "DENIED".to_owned(),
                ));
            }
        }
    }

    // get unwrapped object for encryption but preserve original wrapped object
    let unwrapped_object = match owm.object() {
        Object::Certificate { .. } => owm.object().clone(),
        _ => kms.get_unwrapped(owm.id(), owm.object(), user).await?,
    };

    // Create a new ObjectWithMetadata with the unwrapped object for encryption operations
    let mut unwrapped_owm = owm.clone();
    unwrapped_owm.set_object(unwrapped_object);

    // Second-stage enforcement: validate the retrieved key's stored attributes.
    enforce_kmip_algorithm_policy_for_retrieved_key(
        &kms.params,
        "Encrypt",
        unwrapped_owm.id(),
        &unwrapped_owm,
    )?;

    // plaintext length for logging
    let plaintext_len = request.data.as_ref().map_or(0, |d| d.len());

    // Enforce UsageLimits (byte unit). The vector CS-BC-M-7-21 sets a UsageLimitsTotal=16 (bytes)
    // and performs two 16-byte ECB encrypts expecting the second to fail with PermissionDenied.
    // We implement a simple in-memory decrement persisted via attributes/state update.
    // NOTE: For durability a DB column would be better; for conformance tests this suffices.
    if let Ok(attrs) = unwrapped_owm.object().attributes() {
        if let Some(usage_limits) = attrs.usage_limits.as_ref() {
            // Only enforce for Byte unit
            if matches!(usage_limits.usage_limits_unit, UsageLimitsUnit::Byte) {
                let remaining = usage_limits.usage_limits_total; // total remaining bytes allowed
                let needed = i64::try_from(plaintext_len).map_or(i64::MAX, |v| v);
                if remaining < needed {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Permission_Denied,
                        "DENIED".to_owned(),
                    ));
                }
            }
        }
    }

    // It may be a bulk encryption request; if not, fallback to single encryption
    let res = match BulkData::deserialize(data) {
        Ok(bulk_data) => {
            // It is a bulk encryption request
            encrypt_bulk(&unwrapped_owm, &kms.params, request, bulk_data)
        }
        Err(_) => {
            // fallback to single encryption
            encrypt_single(&unwrapped_owm, &kms.params, &request)
        }
    }?;

    // Post-encryption: decrement usage limits if enforced.
    if let Ok(attrs) = unwrapped_owm.object_mut().attributes_mut() {
        if let Some(ref mut usage_limits) = attrs.usage_limits {
            if matches!(usage_limits.usage_limits_unit, cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UsageLimitsUnit::Byte) {
                if let Ok(p) = i64::try_from(plaintext_len) {
                    usage_limits.usage_limits_total -= p;
                } else {
                    usage_limits.usage_limits_total = 0;
                }
                if usage_limits.usage_limits_total < 0 {
                    usage_limits.usage_limits_total = 0;
                }
            }
        }
    }

    // Copy updated usage limits from unwrapped_owm back to original owm for persistence
    if let (Ok(unwrapped_attrs), Ok(original_attrs)) = (
        unwrapped_owm.object().attributes(),
        owm.object_mut().attributes_mut(),
    ) {
        if let Some(unwrapped_usage_limits) = unwrapped_attrs.usage_limits.as_ref() {
            if let Some(ref mut original_usage_limits) = original_attrs.usage_limits {
                original_usage_limits.usage_limits_total =
                    unwrapped_usage_limits.usage_limits_total;
            }
        }
    }

    // Persist updated attributes (including possibly decremented UsageLimits) so subsequent
    // operations observe the reduced remaining total. We ignore failure here only if the
    // encryption itself succeeded; but propagate errors to surface DB issues.
    if let Ok(attributes) = owm.object().attributes() {
        if let Err(e) = kms
            .database
            .update_object(
                owm.id(),
                owm.object(),
                attributes,
                None, // tags unchanged
            )
            .await
        {
            return Err(KmsError::ServerError(format!(
                "Encrypt: failed to persist updated usage limits: {e}"
            )));
        }
    }

    info!(
        uid = owm.id(),
        user = user,
        "Encrypted data of: {} bytes -> ciphertext length: {}",
        plaintext_len,
        res.data.as_ref().map_or(0, Vec::len),
    );
    Ok(res)
}

/// Encrypt using an encryption oracle.
///
/// # Arguments
/// * `kms` - the KMS
/// * `request` - the encrypted request
/// * `data` - the data to encrypt
/// * `uid` - the unique identifier of the key
/// * `prefix` - the prefix of the encryption oracle
///
/// # Returns
/// * the encrypted response
async fn encrypt_using_encryption_oracle(
    kms: &KMS,
    request: &Encrypt,
    data: &Zeroizing<Vec<u8>>,
    uid: &str,
    prefix: &str,
) -> KResult<EncryptResponse> {
    let lock = kms.encryption_oracles.read().await;
    let encryption_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "Encrypt: unknown encryption oracle prefix: {prefix}"
        ))
    })?;
    let ca = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| CryptoAlgorithm::from_kmip(cp).transpose())
        .transpose()?;
    let encrypted_content = encryption_oracle
        .encrypt(
            uid,
            data,
            ca.clone(),
            request.authenticated_encryption_additional_data.as_deref(),
        )
        .await?;
    debug!(
        "algorithm: {ca:?}, ciphertext length: {}",
        encrypted_content.ciphertext.len()
    );

    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        data: Some(encrypted_content.ciphertext.clone()),
        i_v_counter_nonce: encrypted_content.iv,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: encrypted_content.tag,
    })
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
) -> KResult<EncryptResponse> {
    match owm.object() {
        Object::SymmetricKey { .. } => encrypt_with_symmetric_key(request, owm),
        Object::PublicKey { .. } => encrypt_with_public_key(request, server_params, owm),
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => encrypt_with_certificate(request, server_params, owm.id(), certificate_value),
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
    mut request: Encrypt,
    bulk_data: BulkData,
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
                request.data = Some(plaintext.clone());
                let (key_bytes, cipher) = get_key_and_cipher(&request, owm)?;
                let nonce = request
                    .i_v_counter_nonce
                    .clone()
                    .unwrap_or(random_nonce(cipher)?);
                let padding_method = request
                    .cryptographic_parameters
                    .as_ref()
                    .and_then(|cp| cp.padding_method)
                    .unwrap_or(PaddingMethod::PKCS5);
                let (ciphertext, tag) = sym_encrypt(
                    cipher,
                    &key_bytes,
                    &nonce,
                    aad,
                    &plaintext,
                    Some(padding_method),
                )?;
                // concatenate nonce || ciphertext || tag
                let nct = [nonce.as_slice(), ciphertext.as_slice(), tag.as_slice()].concat();
                ciphertexts.push(Zeroizing::new(nct));
            }
        }
        Object::PublicKey { .. } => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response = encrypt_with_public_key(&request, server_params, owm)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response =
                    encrypt_with_certificate(&request, server_params, owm.id(), certificate_value)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "Encrypt bulk: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }

    debug!("<== encrypted {} ciphertexts", ciphertexts.len());
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(BulkData::new(ciphertexts).serialize()?.to_vec()),
        i_v_counter_nonce: None,
        correlation_value: request.correlation_value,
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_symmetric_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    trace!("entering. owm: {}", owm.attributes());
    let (key_bytes, aead) = get_key_and_cipher(request, owm)?;
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    // ECB (nonce_size == 0) MUST NOT output or require a nonce; do not generate one.
    let nonce = if aead.nonce_size() == 0 {
        Vec::new()
    } else {
        request
            .i_v_counter_nonce
            .clone()
            .unwrap_or(random_nonce(aead)?)
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
        trace!("plaintext (ECB): {plaintext:?}, aad: {aad:?}, padding_method: {padding_method:?}");
    } else {
        trace!(
            "plaintext: {plaintext:?}, nonce: {nonce:?}, aad: {aad:?}, padding_method: \
             {padding_method:?}"
        );
    }
    let (ciphertext, tag) = sym_encrypt(
        aead,
        &key_bytes,
        &nonce,
        aad,
        plaintext,
        Some(padding_method),
    )?;

    if aead.nonce_size() == 0 {
        trace!("ciphertext (ECB): {ciphertext:?}");
    } else {
        trace!("ciphertext: {ciphertext:?}, tag: {tag:?},");
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
            Some(nonce)
        } else {
            None
        },
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: adjusted_tag,
    })
}

fn get_key_and_cipher(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<(Zeroizing<Vec<u8>>, SymCipher)> {
    trace!("entering");
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
    let key_bytes = key_block.key_bytes()?;
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
        KeyFormatType::CoverCryptPublicKey => {
            CoverCryptEncryption::instantiate(Covercrypt::default(), owm.id(), owm.object())?
                .encrypt(request)
                .map_err(Into::into)
        }
        KeyFormatType::TransparentECPublicKey
        | KeyFormatType::TransparentRSAPublicKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            let plaintext = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
            })?;
            trace!(
                "matching on key format type: {:?}",
                key_block.key_format_type
            );
            let public_key = kmip_public_key_to_openssl(owm.object())?;
            trace!("OpenSSL Public Key instantiated before encryption");
            encrypt_with_pkey(request, server_params, owm.id(), plaintext, &public_key)
        }
        other => Err(KmsError::NotSupported(format!(
            "encryption with public keys of format: {other}"
        ))),
    }
}

fn encrypt_with_pkey(
    request: &Encrypt,
    #[cfg(feature = "non-fips")] server_params: &ServerParams,
    #[cfg(not(feature = "non-fips"))] _server_params: &ServerParams,
    key_id: &str,
    plaintext: &[u8],
    public_key: &PKey<Public>,
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
            )?
        }
        #[cfg(feature = "non-fips")]
        Id::EC | Id::X25519 | Id::ED25519 => {
            enforce_ecies_fixed_suite_for_pkey_id(
                server_params,
                "Encrypt",
                key_id,
                public_key.id(),
            )?;
            ecies_encrypt(public_key, plaintext)?
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
            PaddingMethod::None => ckm_rsa_aes_key_wrap(public_key, hashing_fn, plaintext)?,
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
) -> KResult<EncryptResponse> {
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let cert = X509::from_der(certificate_value)
        .map_err(|e| KmipError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
    let public_key = cert.public_key().map_err(|e| {
        KmipError::ConversionError(format!("invalid certificate public key: error: {e:?}"))
    })?;
    encrypt_with_pkey(request, server_params, key_id, plaintext, &public_key)
}

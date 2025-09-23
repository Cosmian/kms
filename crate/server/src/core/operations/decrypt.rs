use std::sync::Arc;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::{
    DecryptionSystem, cover_crypt::decryption::CovercryptDecryption,
    elliptic_curves::ecies::ecies_decrypt, rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_decrypt,
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
    cosmian_kms_interfaces::{CryptoAlgorithm, ObjectWithMetadata, SessionParams},
};
use cosmian_logger::{debug, info, trace};
use openssl::pkey::{Id, PKey, Private};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS,
        uid_utils::{has_prefix, uids_from_unique_identifier},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<DecryptResponse> {
    trace!("{}", serde_json::to_string(&request)?);
    let data = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms, params.clone())
        .await
        .context("Decrypt")?;
    debug!("candidate uids: {uids:?}");

    // Determine which UID to select. The decision process is as follows: loop through the uids
    // 1. If the UID has a prefix, try using that
    // 2. If the UID does not have a prefix, fetch the corresponding object and check that
    //   a- the object is active
    //   b- the object is a Private Key, a Symmetric Key
    //   c- the object is authorized for Decryption
    //
    // Permissions checks are done AFTER the object is fetched in the default database
    // to avoid calling `database.is_object_owned_by()` and hence a double call to the DB
    // for each uid. This is also based on the high probability that there is still a single object
    // in the candidates' list.
    let mut selected_owm = None;
    for uid in uids {
        if let Some(prefix) = has_prefix(&uid) {
            if !kms
                .database
                .is_object_owned_by(&uid, user, params.clone())
                .await?
            {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false, params.clone())
                    .await?;
                if !ops
                    .iter()
                    .any(|p| [KmipOperation::Decrypt, KmipOperation::Get].contains(p))
                {
                    debug!("{user} is not authorized to decrypt using: {uid}");
                    continue
                }
            }
            debug!("{user} is authorized to decrypt using: {uid}");
            return decrypt_using_encryption_oracle(kms, &request, &uid, prefix).await;
        }

        //Default database
        let owm = kms
            .database
            .retrieve_object(&uid, params.clone())
            .await?
            .ok_or_else(|| {
                debug!("failed to retrieve the key: {uid}");
                KmsError::Kmip21Error(
                    ErrorReason::Item_Not_Found,
                    format!("Decrypt: failed to retrieve the key: {uid}"),
                )
            })?;
        if owm.state() != State::Active {
            debug!("{uid} is not active");
            continue
        }
        // If an HSM wraps the object, likely the wrapping will be done with NoEncoding
        // and the attributes of the object will be empty. Use the metadata attributes.
        let attributes = owm
            .object()
            .attributes()
            .unwrap_or_else(|_| owm.attributes());
        if !attributes.is_usage_authorized_for(CryptographicUsageMask::Decrypt)? {
            debug!("{uid} is not authorized for decryption");
            continue
        }
        //check user permissions - owner can always decrypt
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(&uid, user, false, params.clone())
                .await?;
            if !ops
                .iter()
                .any(|p| [KmipOperation::Decrypt, KmipOperation::Get].contains(p))
            {
                debug!("{user} is not authorized to decrypt using: {uid}");
                continue
            }
        }
        debug!("{user} is authorized to decrypt using: {uid}");
        // user is authorized to decrypt with the key
        if let Object::SymmetricKey { .. } = owm.object() {
            selected_owm = Some(owm);
            break
        }
        if let Object::PrivateKey { .. } = owm.object() {
            //Is it a Covercrypt secret key?
            #[cfg(feature = "non-fips")]
            if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                // does it have an access access structure that allows decryption?
                use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::access_policy_from_attributes;
                if access_policy_from_attributes(attributes).is_err() {
                    continue
                }
            }
            selected_owm = Some(owm);
            break
        }
    }
    let mut owm = selected_owm.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!("Decrypt: no valid key for id: {unique_identifier}"),
        )
    })?;

    // if the key is wrapped, we need to unwrap it
    owm.set_object(
        kms.get_unwrapped(owm.id(), owm.object(), user, params)
            .await
            .with_context(|| format!("Decrypt: the key: {}, cannot be unwrapped.", owm.id()))?,
    );

    let res = BulkData::deserialize(data).map_or_else(
        |_| {
            decrypt_single(
                #[cfg(feature = "non-fips")]
                kms,
                &owm,
                &request,
            )
        },
        |bulk_data| {
            decrypt_bulk(
                #[cfg(feature = "non-fips")]
                kms,
                &owm,
                &request,
                bulk_data,
            )
        },
    )?;

    info!(
        uid = owm.id(),
        user = user,
        "Decrypted ciphertext of: {} bytes -> plaintext length: {}",
        request.data.as_ref().map_or(0, Vec::len),
        res.data.as_ref().map_or(0, |d| d.len()),
    );

    Ok(res)
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
async fn decrypt_using_encryption_oracle(
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
        .encryption_oracles
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
    #[cfg(feature = "non-fips")] kms: &KMS,
    owm: &ObjectWithMetadata,
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
                let response = decrypt_with_covercrypt(kms, owm, &request)?;
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
                let response = decrypt_with_private_key(owm, &request)?;
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
                    ))
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
            )))
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
    #[cfg(feature = "non-fips")] kms: &KMS,
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> KResult<DecryptResponse> {
    trace!("entering");
    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptSecretKey => decrypt_with_covercrypt(kms, owm, request),

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            trace!(
                "matching on public key format type: {:?}",
                key_block.key_format_type
            );
            decrypt_with_private_key(owm, request)
        }

        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            decrypt_single_with_symmetric_key(owm, request)?
        }

        other => Err(KmsError::NotSupported(format!(
            "decryption with keys of format: {other}"
        ))),
    }
}

#[cfg(feature = "non-fips")]
fn decrypt_with_covercrypt(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<DecryptResponse, KmsError> {
    trace!("key id {}", owm.id());
    CovercryptDecryption::instantiate(kms.covercrypt.clone(), owm.id(), owm.object())?
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
    let nonce = request.i_v_counter_nonce.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: the nonce/IV must be provided".to_owned())
    })?;
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let tag = request
        .authenticated_encryption_tag
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let padding_method = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.padding_method)
        .unwrap_or(PaddingMethod::PKCS5);
    trace!(
        "ciphertext: {ciphertext:?}, nonce: {nonce:?}, aad: {aad:?}, tag: {tag:?}, \
         padding_method: {padding_method:?}"
    );
    let plaintext = sym_decrypt(
        aead,
        &key_bytes,
        nonce,
        aad,
        ciphertext,
        tag,
        Some(padding_method),
    )?;
    trace!("plaintext: {plaintext:?}");
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
        .unwrap_or_else(|| {
            key_block
                .cryptographic_algorithm()
                .copied()
                .unwrap_or(CryptographicAlgorithm::AES)
        });
    let block_cipher_mode = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.block_cipher_mode);
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
) -> KResult<DecryptResponse> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;
    let private_key = kmip_private_key_to_openssl(owm.object())?;

    let plaintext = match private_key.id() {
        Id::RSA => decrypt_with_rsa(
            &private_key,
            request.cryptographic_parameters.as_ref(),
            ciphertext,
        )?,
        #[cfg(feature = "non-fips")]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(&private_key, ciphertext)?,
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

fn decrypt_with_rsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    ciphertext: &[u8],
) -> KResult<Zeroizing<Vec<u8>>> {
    let (algorithm, padding, hashing_fn, _) =
        default_cryptographic_parameters(cryptographic_parameters);
    trace!(
        "algorithm: {:?}, padding: {:?}, hashing_fn: {:?}",
        algorithm, padding, hashing_fn
    );

    Ok(match (algorithm, padding) {
        (CryptographicAlgorithm::RSA, PaddingMethod::None) => {
            ckm_rsa_aes_key_unwrap(private_key, hashing_fn, ciphertext)?
        }
        (CryptographicAlgorithm::RSA, PaddingMethod::OAEP) => {
            ckm_rsa_pkcs_oaep_key_decrypt(private_key, hashing_fn, ciphertext)?
        }
        #[cfg(feature = "non-fips")]
        (CryptographicAlgorithm::RSA, PaddingMethod::PKCS1v15) => {
            ckm_rsa_pkcs_decrypt(private_key, ciphertext)?
        }
        _ => kms_bail!("Decrypt: algorithm or padding method not supported for RSA decryption"),
    })
}

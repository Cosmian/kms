use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::{
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Decrypt, DecryptResponse, ErrorReason},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, KeyFormatType,
            PaddingMethod, StateEnumeration, UniqueIdentifier,
        },
    },
    openssl::kmip_private_key_to_openssl,
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::{
        cover_crypt::{attributes, decryption::CovercryptDecryption},
        elliptic_curves::ecies::ecies_decrypt,
        rsa::{
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap,
            rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_decrypt,
        },
        symmetric::aead::{aead_decrypt, AeadCipher},
    },
    DecryptionSystem,
};
use openssl::pkey::{Id, PKey, Private};
use tracing::trace;

use crate::{
    core::{operations::unwrap_key, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail, kms_not_supported,
    result::{KResult, KResultHelper},
};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);

    let owm = get_key(kms, &request, user, params).await?;

    trace!(
        "get_decryption_system: matching on object: {:?}",
        owm.object
    );

    match &owm.object {
        Object::SymmetricKey { .. } => decrypt_with_aead(&request, &owm),
        Object::PrivateKey { .. } => decrypt_with_private_key(&request, &owm),
        other => kms_not_supported!(
            "decrypt: decryption with keys of type: {} is not supported",
            other.object_type()
        ),
    }
}

async fn get_key(
    kms: &KMS,
    request: &Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Decrypt: unique_identifier must be a string")?;
    trace!("decrypt: uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Decrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            if owm.state != StateEnumeration::Active {
                return false
            }
            if object_type == ObjectType::SymmetricKey {
                return true
            }
            if object_type != ObjectType::PrivateKey {
                return false
            }
            if let Ok(attributes) = owm.object.attributes() {
                // is it a Covercrypt secret key?
                if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                    // does it have an access policy that allows decryption?
                    return attributes::access_policy_from_attributes(attributes).is_ok()
                }
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();
    trace!("decrypt: owm_s: {:?}", owm_s);

    // there can only be one key
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_string()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    // unwrap if wrapped
    if owm.object.key_wrapping_data().is_some() {
        let key_block = owm.object.key_block_mut()?;
        unwrap_key(key_block, kms, &owm.owner, params).await?;
    }
    Ok(owm)
}

fn decrypt_with_aead(request: &Decrypt, owm: &ObjectWithMetadata) -> KResult<DecryptResponse> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;
    let key_block = owm.object.key_block()?;
    match key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            // recover the cryptographic algorithm from the request or the key block or default to AES
            let cryptographic_alogrithm = request
                .cryptographic_parameters
                .and_then(|cp| cp.cryptographic_algorithm)
                .unwrap_or(
                    key_block
                        .cryptographic_algorithm()
                        .cloned()
                        .unwrap_or(CryptographicAlgorithm::AES),
                );
            let block_cipher_mode = request
                .cryptographic_parameters
                .and_then(|cp| cp.block_cipher_mode);
            let key_bytes = key_block.key_bytes()?;
            let aead = AeadCipher::from_algorithm_and_key_size(
                cryptographic_alogrithm,
                block_cipher_mode,
                key_bytes.len(),
            )?;
            let nonce = request.iv_counter_nonce.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Decrypt: the nonce/IV must be provided".to_owned())
            })?;
            let aad = request
                .authenticated_encryption_additional_data
                .as_ref()
                .unwrap_or_default();
            let tag = request
                .authenticated_encryption_tag
                .as_ref()
                .unwrap_or_default();
            let plaintext = aead_decrypt(aead, &key_bytes, nonce, aad, ciphertext, tag)?;
            Ok(DecryptResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id.to_string()),
                data: Some(plaintext),
                correlation_value: request.correlation_value.clone(),
            })
        }
        other => kms_not_supported!("symmetric decryption with keys of format: {other}"),
    }
}

fn decrypt_with_private_key(
    request: &Decrypt,
    owm: &ObjectWithMetadata,
) -> KResult<DecryptResponse> {
    let key_block = owm.object.key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::CoverCryptPublicKey => {
            CovercryptDecryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?
                .decrypt(request)
                .map_err(Into::into)
        }

        KeyFormatType::TransparentECPublicKey
        | KeyFormatType::TransparentRSAPublicKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            let ciphertext = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to decrypt must be provided".to_owned())
            })?;
            trace!(
                "get_decryption_system: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let private_key = kmip_private_key_to_openssl(&owm.object)?;
            trace!("get_decryption_system: OpenSSL Private Key instantiated before decryption");
            decrypt_with_pkey(request, &owm.id, ciphertext, &private_key)
        }
        other => kms_not_supported!("decryption with private keys of format: {other}"),
    }
}

fn decrypt_with_pkey(
    request: &Decrypt,
    key_id: &str,
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> KResult<DecryptResponse> {
    let plaintext = match private_key.id() {
        Id::RSA => decrypt_with_rsa(
            private_key,
            request.cryptographic_parameters.as_ref(),
            ciphertext,
            request.authenticated_encryption_additional_data.as_deref(),
        )?,
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(private_key, ciphertext)?,
        other => {
            kms_bail!("Decrypt: private key type not supported: {other:?}")
        }
    };
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_string()),
        data: Some(plaintext),
        correlation_value: request.correlation_value.clone(),
    })
}

fn decrypt_with_rsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    ct: &[u8],
    aad: Option<&[u8]>,
) -> KResult<Vec<u8>> {
    let (algorithm, padding, hashing_fn) = cryptographic_parameters
        .map(|cp| {
            (
                cp.cryptographic_algorithm
                    .unwrap_or(CryptographicAlgorithm::RSA),
                cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
            )
        })
        .unwrap_or_else(|| {
            (
                // default to CKM_RSA_PKCS_OAEP_KEY_WRAP
                CryptographicAlgorithm::RSA,
                PaddingMethod::OAEP,
                HashingAlgorithm::SHA256,
            )
        });

    if padding != PaddingMethod::OAEP {
        kms_bail!("Unable to decrypt with RSA: padding method not supported: {padding:?}")
    }
    let plaintext = match algorithm {
        CryptographicAlgorithm::AES => rsa_oaep_aes_gcm_decrypt(private_key, hashing_fn, ct, aad)?,
        CryptographicAlgorithm::RSA => ckm_rsa_pkcs_oaep_key_unwrap(private_key, hashing_fn, ct)?,
        x => {
            kms_bail!("Unable to decrypt with RSA: algorithm not supported for decrypting: {x:?}")
        }
    };
    Ok(plaintext)
}

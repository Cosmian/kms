use cloudproof::reexport::cover_crypt::Covercrypt;
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::trace;

use cosmian_kmip::{
    crypto::{
        cover_crypt::encryption::CoverCryptEncryption,
        EncryptionSystem,
        rsa::{
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_encrypt,
            rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_encrypt,
        },
        symmetric::aead::{aead_encrypt, AeadCipher, random_nonce},
    },
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, KeyFormatType,
            PaddingMethod, StateEnumeration, UniqueIdentifier,
        },
    },
    KmipError,
    openssl::kmip_public_key_to_openssl,
};
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::ecies::ecies_encrypt;
use cosmian_kms_client::access::ObjectOperationType;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS, operations::unwrap_key},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    trace!("operations::encrypt: {}", serde_json::to_string(&request)?);

    let owm = get_key(kms, &request, user, params).await?;
    trace!("get_encryption_system: unwrap done (if required)");

    match &owm.object {
        Object::SymmetricKey { .. } => encrypt_with_aead(&request, &owm),
        Object::PublicKey { .. } => encrypt_with_public_key(&request, &owm),
        Object::Certificate {
            certificate_value, ..
        } => encrypt_with_certificate(&request, &owm.id, certificate_value),
        other => kms_bail!(KmsError::NotSupported(format!(
            "encrypt: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

async fn get_key(
    kms: &KMS,
    request: &Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Encrypt: the unique identifier or tags must be a string")?
        .to_string();
    trace!("operations::encrypt: uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Encrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active
                && (object_type == ObjectType::PublicKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::Certificate)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    trace!("operations::encrypt: owm_s: {:?}", owm_s);
    // there can only be one key
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    // the key must be active
    if owm.state != StateEnumeration::Active {
        kms_bail!(KmsError::InconsistentOperation(
            "encrypt: the server cannot if the key is not active".to_owned()
        ));
    }

    // unwrap if wrapped
    match &mut owm.object {
        Object::Certificate { .. } => {}
        _ => {
            if owm.object.key_wrapping_data().is_some() {
                let key_block = owm.object.key_block_mut()?;
                unwrap_key(key_block, kms, &owm.owner, params).await?;
            }
        }
    }
    Ok(owm)
}

fn encrypt_with_aead(request: &Encrypt, owm: &ObjectWithMetadata) -> KResult<EncryptResponse> {
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let key_block = owm.object.key_block()?;
    match key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            // recover the cryptographic algorithm from the request or the key block or default to AES
            let cryptographic_algorithm = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.cryptographic_algorithm)
                .unwrap_or(
                    key_block
                        .cryptographic_algorithm()
                        .copied()
                        .unwrap_or(CryptographicAlgorithm::AES),
                );
            let block_cipher_mode = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.block_cipher_mode);
            let key_bytes = key_block.key_bytes()?;
            let aead = AeadCipher::from_algorithm_and_key_size(
                cryptographic_algorithm,
                block_cipher_mode,
                key_bytes.len(),
            )?;
            let nonce = request
                .iv_counter_nonce
                .clone()
                .unwrap_or(random_nonce(aead)?);
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            let (ciphertext, tag) = aead_encrypt(aead, &key_bytes, &nonce, aad, plaintext)?;
            Ok(EncryptResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id.to_string()),
                data: Some(ciphertext),
                iv_counter_nonce: Some(nonce),
                correlation_value: request.correlation_value.clone(),
                authenticated_encryption_tag: Some(tag),
            })
        }
        other => Err(KmsError::NotSupported(format!(
            "symmetric encryption with keys of format: {other}"
        ))),
    }
}

fn encrypt_with_public_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    let key_block = owm.object.key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::CoverCryptPublicKey => {
            CoverCryptEncryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?
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
                "get_encryption_system: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let public_key = kmip_public_key_to_openssl(&owm.object)?;
            trace!("get_encryption_system: OpenSSL Public Key instantiated before encryption");
            encrypt_with_pkey(request, &owm.id, plaintext, &public_key)
        }
        other => Err(KmsError::NotSupported(format!(
            "encryption with public keys of format: {other}"
        ))),
    }
}

fn encrypt_with_pkey(
    request: &Encrypt,
    key_id: &str,
    plaintext: &[u8],
    public_key: &PKey<Public>,
) -> KResult<EncryptResponse> {
    let ciphertext = match public_key.id() {
        Id::RSA => encrypt_with_rsa(
            public_key,
            request.cryptographic_parameters.as_ref(),
            plaintext,
            request.authenticated_encryption_additional_data.as_deref(),
        )?,
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(public_key, plaintext)?,
        other => {
            kms_bail!("Encrypt: public key type not supported: {other:?}")
        }
    };
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_string()),
        data: Some(ciphertext),
        iv_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_rsa(
    public_key: &PKey<Public>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    plaintext: &[u8],
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
        kms_bail!("Unable to encrypt with RSA: padding method not supported: {padding:?}")
    }
    let ciphertext = match algorithm {
        CryptographicAlgorithm::AES => {
            rsa_oaep_aes_gcm_encrypt(public_key, hashing_fn, plaintext, aad)?
        }
        CryptographicAlgorithm::RSA => {
            ckm_rsa_pkcs_oaep_encrypt(public_key, hashing_fn, plaintext)?
        }
        x => {
            kms_bail!("Unable to encrypt with RSA: algorithm not supported for encrypting: {x:?}")
        }
    };
    Ok(ciphertext)
}

fn encrypt_with_certificate(
    request: &Encrypt,
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
    encrypt_with_pkey(request, key_id, plaintext, &public_key)
}

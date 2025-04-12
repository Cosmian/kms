use base64::{engine::general_purpose, Engine};
use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask, PaddingMethod},
    kmip_2_1::{
        kmip_data_structures::{
            KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
        },
        kmip_objects::{
            Certificate, Object, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey,
        },
        kmip_types::{CryptographicAlgorithm, EncodingOption, KeyFormatType, WrappingMethod},
    },
};
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use super::WRAPPING_SECRET_LENGTH;
#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::ecies::ecies_encrypt;
#[cfg(not(feature = "fips"))]
use crate::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_key_wrap;
use crate::{
    crypto::{
        password_derivation::derive_key_from_password,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_wrap,
        },
        symmetric::{
            rfc5649::rfc5649_wrap,
            symmetric_ciphers::{encrypt, random_nonce, SymCipher},
        },
        wrap::common::rsa_parameters,
        FIPS_MIN_SALT_SIZE,
    },
    crypto_bail, crypto_error,
    error::{result::CryptoResult, CryptoError},
    openssl::kmip_public_key_to_openssl,
};

/// Wrap a key using a password
///
/// # Arguments
/// * `key` - the key to wrap
/// * `salt` - the salt to use for the key derivation
/// * `wrapping_password` - the password to use for the key derivation
/// # Returns
/// * `KResult<Vec<u8>>` - the wrapped key
pub fn wrap_key_bytes(
    key: &[u8],
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    wrapping_password: &str,
) -> Result<Vec<u8>, CryptoError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(salt, wrapping_password.as_bytes())?;
    rfc5649_wrap(key, wrapping_secret.as_ref()).map_err(|e| CryptoError::Default(e.to_string()))
}

// The purpose of this function is to check the block cipher mode in the encryption key information against the wrapping key
// It verifies the BlockCipherMode is only used for a `SymmetricKey` object
fn check_block_cipher_mode_in_encryption_key_information(
    wrapping_key: &Object,
    key_wrapping_specification: &KeyWrappingSpecification,
) -> CryptoResult<()> {
    if let Object::SymmetricKey { .. } = wrapping_key {
        // Do nothing
    } else if let Some(encryption_key_information) = key_wrapping_specification
        .encryption_key_information
        .as_ref()
    {
        if let Some(cryptographic_parameters) =
            encryption_key_information.cryptographic_parameters.as_ref()
        {
            if cryptographic_parameters.block_cipher_mode.is_some() {
                crypto_bail!("BlockCipherMode is only used for a SymmetricKey object")
            }
        }
    }
    Ok(())
}

/// Wrap a key block with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `rng` - the random number generator
/// * `object_key_block` - the key block of the object to wrap
/// * `wrapping_key` - the wrapping key
/// * `key_wrapping_specification` - the key wrapping specification
/// # Returns
/// * `KResult<()>` - the result of the operation
pub fn wrap_key_block(
    object_key_block: &mut KeyBlock,
    wrapping_key: &Object,
    key_wrapping_specification: &KeyWrappingSpecification,
) -> Result<(), CryptoError> {
    let data_to_wrap = key_data_to_wrap(&object_key_block, key_wrapping_specification)?;
    check_block_cipher_mode_in_encryption_key_information(
        wrapping_key,
        key_wrapping_specification,
    )?;
    let ciphertext = wrap(
        wrapping_key,
        &key_wrapping_specification.get_key_wrapping_data(),
        &data_to_wrap,
        key_wrapping_specification.get_additional_authenticated_data(),
    )?;
    update_key_block_with_wrapped_key(object_key_block, key_wrapping_specification, ciphertext);

    Ok(())
}

/// Post process the wrapped key block
/// The key block is updated with the wrapped key
/// The key wrapping data is updated with the key wrapping data
/// # Arguments
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// * `ciphertext` - the wrapped key
pub fn update_key_block_with_wrapped_key(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    wrapped_key: Vec<u8>,
) {
    // wrap the key based on the encoding
    match key_wrapping_specification.get_encoding() {
        EncodingOption::TTLVEncoding => {
            object_key_block.key_value = Some(KeyValue {
                key_material: KeyMaterial::ByteString(wrapped_key.into()),
                // not clear whether this should be filled or not
                attributes: object_key_block
                    .key_value
                    .as_mut()
                    .and_then(|kv| kv.attributes.clone()),
            });
        }
        EncodingOption::NoEncoding => {
            if let Some(key_value) = &mut object_key_block.key_value {
                key_value.key_material = KeyMaterial::ByteString(wrapped_key.into());
            }
        }
    }
    object_key_block.key_wrapping_data = Some(key_wrapping_specification.get_key_wrapping_data());
}

/// Determine the Key data to wrap
/// The key data is determined based on the encoding
/// # Arguments
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// # Returns
/// * `KResult<Zeroizing<Vec<u8>>>` - the key data to wrap
pub fn key_data_to_wrap(
    object_key_block: &&mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if object_key_block.key_wrapping_data.is_some() {
        crypto_bail!("unable to wrap the key: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_specification.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            crypto_bail!("Unable to wrap the key: wrapping method is not supported: {x:?}")
        }
    }
    // wrap the key based on the encoding
    Ok(match key_wrapping_specification.get_encoding() {
        EncodingOption::TTLVEncoding => {
            let ttlv_bytes = object_key_block
                .key_value
                .as_ref()
                .map(|kv| kv.to_ttlv_bytes(object_key_block.key_format_type))
                .transpose()?
                .ok_or_else(|| crypto_error!("Unable to wrap the key: key value is not set"))?;
            Zeroizing::from(ttlv_bytes)
        }
        EncodingOption::NoEncoding => object_key_block.key_bytes()?,
    })
}

/// Encrypt bytes using the wrapping key
pub(crate) fn wrap(
    wrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
    additional_authenticated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    trace!("wrap: with object type: {:?}", wrapping_key.object_type());
    match wrapping_key {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => {
            let cert = X509::from_der(certificate_value)
                .map_err(|e| CryptoError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
            let public_key = cert.public_key().map_err(|e| {
                CryptoError::ConversionError(format!(
                    "invalid certificate public key: error: {e:?}"
                ))
            })?;
            wrap_with_public_key(&public_key, key_wrapping_data, key_to_wrap)
        }
        Object::PGPKey(PGPKey { key_block, .. })
        | Object::SecretData(SecretData { key_block, .. })
        | Object::SplitKey(SplitKey { key_block, .. })
        | Object::PrivateKey(PrivateKey { key_block })
        | Object::PublicKey(PublicKey { key_block })
        | Object::SymmetricKey(SymmetricKey { key_block }) => {
            trace!("wrap: key_block: {}", key_block);
            // wrap the wrapping key if necessary
            if key_block.key_wrapping_data.is_some() {
                crypto_bail!(
                    "unable to wrap key: wrapping key is wrapped and that is not supported"
                )
            }

            // Make sure that the key used to wrap can be used to wrap.
            if !wrapping_key
                .attributes()?
                .is_usage_authorized_for(CryptographicUsageMask::WrapKey)?
            {
                return Err(CryptoError::Kmip(
                    "CryptographicUsageMask not authorized for WrapKey".to_owned(),
                ))
            }

            let ciphertext = match key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    let cryptographic_parameters = key_wrapping_data
                        .encryption_key_information
                        .clone()
                        .and_then(|info| info.cryptographic_parameters);
                    let cryptographic_algorithm = cryptographic_parameters
                        .as_ref()
                        .and_then(|params| params.cryptographic_algorithm)
                        .unwrap_or(CryptographicAlgorithm::AES);
                    if cryptographic_algorithm == CryptographicAlgorithm::RSA {
                        crypto_bail!(CryptoError::NotSupported(
                            "Can't use RSA algorithm for AES wrapping key".to_owned()
                        ))
                    }
                    let block_cipher_mode = cryptographic_parameters
                        .as_ref()
                        .and_then(|params| params.block_cipher_mode)
                        .unwrap_or(BlockCipherMode::NISTKeyWrap);
                    debug!(
                        "symmetric wrapping using {cryptographic_algorithm} and \
                         block_cipher_mode: {:?}",
                        block_cipher_mode
                    );
                    let key_bytes = key_block.key_bytes()?;
                    let aad = additional_authenticated_data.unwrap_or_default();
                    if block_cipher_mode == BlockCipherMode::GCM {
                        // wrap using aes GCM
                        let aead = SymCipher::from_algorithm_and_key_size(
                            cryptographic_algorithm,
                            Some(block_cipher_mode),
                            key_bytes.len(),
                        )?;

                        let nonce = random_nonce(aead)?;

                        let (ct, authenticated_encryption_tag) =
                            encrypt(aead, &key_bytes, &nonce, aad, key_to_wrap)?;
                        let mut ciphertext = Vec::with_capacity(
                            nonce.len() + ct.len() + authenticated_encryption_tag.len(),
                        );
                        ciphertext.extend_from_slice(&nonce);
                        ciphertext.extend_from_slice(&ct);
                        ciphertext.extend_from_slice(&authenticated_encryption_tag);

                        trace!(
                            "wrap: nonce: {}, aad: {}, tag: {}",
                            general_purpose::STANDARD.encode(&nonce),
                            general_purpose::STANDARD.encode(aad),
                            general_purpose::STANDARD.encode(&authenticated_encryption_tag),
                        );

                        Ok(ciphertext)
                    } else {
                        // wrap using rfc_5649
                        let ciphertext = rfc5649_wrap(key_to_wrap, &key_bytes)?;
                        Ok(ciphertext)
                    }
                }
                KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentRSAPublicKey => {
                    // convert to transparent key and wrap
                    // note: when moving to full openssl this double conversion will be unnecessary
                    let p_key = kmip_public_key_to_openssl(wrapping_key)?;
                    wrap_with_public_key(&p_key, key_wrapping_data, key_to_wrap)
                }
                // this really is SPKI
                KeyFormatType::PKCS8 => {
                    let p_key = PKey::public_key_from_der(&key_block.key_bytes()?)?;
                    wrap_with_public_key(&p_key, key_wrapping_data, key_to_wrap)
                }
                x => {
                    crypto_bail!(
                        "Unable to wrap key: wrapping key: key format not supported for wrapping: \
                         {x:?}"
                    )
                }
            }?;
            Ok(ciphertext)
        }
        _ => Err(CryptoError::NotSupported(format!(
            "Wrapping key type not supported: {:?}",
            wrapping_key.object_type()
        ))),
    }
}

fn wrap_with_public_key(
    public_key: &PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match public_key.id() {
        Id::RSA => wrap_with_rsa(public_key, key_wrapping_data, key_to_wrap),
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(public_key, key_to_wrap),
        other => Err(crypto_error!(
            "Unable to wrap key: wrapping public key type not supported: {other:?}"
        )),
    }
}

fn wrap_with_rsa(
    public_key: &PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (algorithm, padding, hashing_fn) = rsa_parameters(key_wrapping_data);
    debug!("wrapping with RSA {algorithm} {padding:?} {hashing_fn:?} ");
    match algorithm {
        CryptographicAlgorithm::RSA => match padding {
            PaddingMethod::None => ckm_rsa_aes_key_wrap(public_key, hashing_fn, key_to_wrap),
            PaddingMethod::OAEP => ckm_rsa_pkcs_oaep_key_wrap(public_key, hashing_fn, key_to_wrap),
            #[cfg(not(feature = "fips"))]
            PaddingMethod::PKCS1v15 => ckm_rsa_pkcs_key_wrap(public_key, key_to_wrap),
            _ => crypto_bail!(
                "Unable to wrap key with RSA: padding method not supported: {padding:?}"
            ),
        },
        x => {
            crypto_bail!("Unable to wrap key with RSA: algorithm not supported for wrapping: {x:?}")
        }
    }
}

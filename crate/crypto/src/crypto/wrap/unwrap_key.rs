use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask, PaddingMethod},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, EncodingOption, KeyFormatType},
    },
};
use openssl::pkey::{Id, PKey, Private};
use x509_parser::nom::AsBytes;
use zeroize::Zeroizing;

use super::WRAPPING_SECRET_LENGTH;
#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::ecies::ecies_decrypt;
#[cfg(not(feature = "fips"))]
use crate::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_key_unwrap;
use crate::{
    crypto::{
        password_derivation::derive_key_from_password,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_unwrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap,
        },
        symmetric::{
            rfc5649::rfc5649_unwrap,
            symmetric_ciphers::{decrypt, SymCipher},
        },
        wrap::common::rsa_parameters,
        FIPS_MIN_SALT_SIZE,
    },
    crypto_bail,
    error::{result::CryptoResultHelper, CryptoError},
    openssl::kmip_private_key_to_openssl,
};

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

/// Unwrap a key using a password
pub fn unwrap_key_bytes(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    key: &[u8],
    wrapping_password: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(salt, wrapping_password.as_bytes())?;
    rfc5649_unwrap(key, wrapping_secret.as_ref()).map_err(|e| CryptoError::Default(e.to_string()))
}

/// Unwrap a key block with a wrapping key
///
/// # Arguments
/// * `object_key_block` - the key block of the object to unwrap
/// * `unwrapping_key` - the unwrapping key
/// # Returns
/// * `KResult<()>` - the result of the operation
pub fn unwrap_key_block(
    object_key_block: &mut KeyBlock,
    unwrapping_key: &Object,
) -> Result<(), CryptoError> {
    // check that the key wrapping data is present
    let key_wrapping_data = object_key_block
        .key_wrapping_data
        .as_ref()
        .context("unable to unwrap key: key wrapping data is missing")?;

    let Some(KeyValue::ByteString(wrapped_key)) = object_key_block.key_value.as_ref() else {
        crypto_bail!("unable to unwrap key: key value is not a byte string")
    };

    let key_value = unwrap(
        unwrapping_key,
        key_wrapping_data,
        wrapped_key,
        object_key_block.key_format_type,
    )?;

    // update the key block with the unwrapped key
    object_key_block.key_value = Some(key_value);
    object_key_block.key_wrapping_data = None;

    Ok(())
}

// pub struct WrappedKey {
//     pub key_bytes: Zeroizing<Vec<u8>>,
//     pub attributes: Option<Attributes>,
//     pub encoding: EncodingOption,
// }

// /// Recover the wrapped key from the key block and key wrapping data
// /// # Arguments
// /// * `object_key_block` - the key block of the object to unwrap
// /// * `key_wrapping_data` - the key wrapping data
// /// # Returns
// /// * `KResult<(Vec<u8>, Option<Attributes>, EncodingOption)>` - the recovered wrapped key, attributes, and encoding
// ///
// pub fn recover_wrapped_key(
//     object_key_block: &KeyBlock,
//     key_wrapping_data: &KeyWrappingData,
// ) -> Result<WrappedKey, CryptoError> {
//     // check that the wrapping method is supported
//     if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
//         crypto_bail!("unable to unwrap key: only the Encrypt unwrapping method is supported")
//     }

//     let encoding = key_wrapping_data.get_encoding();
//     Ok(match encoding {
//         EncodingOption::TTLVEncoding => WrappedKey {
//             key_bytes: object_key_block.key_bytes()?,
//             attributes: object_key_block.attributes().ok().cloned(),
//             encoding,
//         },
//         EncodingOption::NoEncoding => {
//             let (bytes, attributes) = object_key_block.key_bytes_and_attributes()?;
//             WrappedKey {
//                 key_bytes: bytes,
//                 attributes: attributes.cloned(),
//                 encoding,
//             }
//         }
//     })
// }

/// Unwrap a key using a wrapping key
///
/// # Arguments
/// * `unwrapping_key` - the unwrapping key
/// * `key_wrapping_data` - the key wrapping data
/// * `wrapped_key` - the wrapped key
/// * `key_format_type` - the unwrapped key expected key format type
/// * `aad` - the additional authenticated data
///
/// # Returns
/// * `KResult<KeyValue>` - the unwrapped key
pub(crate) fn unwrap(
    unwrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    wrapped_key: &[u8],
    key_format_type: KeyFormatType,
) -> Result<KeyValue, CryptoError> {
    // Make sure that the key used to unwrap can be used to unwrap.
    if !unwrapping_key
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::UnwrapKey)?
    {
        return Err(CryptoError::Kmip(
            "CryptographicUsageMask not authorized for UnwrapKey".to_owned(),
        ))
    }

    let unwrapping_key_block = unwrapping_key
        .key_block()
        .context("Unable to unwrap: unwrapping key is not a key")?;
    // unwrap the unwrapping key if necessary
    if unwrapping_key_block.key_wrapping_data.is_some() {
        crypto_bail!("unable to unwrap key: unwrapping key is wrapped and that is not supported")
    }

    let plaintext = match unwrapping_key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey => {
            unwrap_with_symmetric_key(key_wrapping_data, wrapped_key, unwrapping_key_block)
        }
        KeyFormatType::TransparentECPrivateKey | KeyFormatType::TransparentRSAPrivateKey => {
            // convert to an openssl private key
            let p_key = kmip_private_key_to_openssl(unwrapping_key)?;
            unwrap_with_private_key(&p_key, key_wrapping_data, wrapped_key)
        }
        KeyFormatType::PKCS8 => {
            let p_key = PKey::private_key_from_der(&unwrapping_key_block.key_bytes()?)?;
            unwrap_with_private_key(&p_key, key_wrapping_data, wrapped_key)
        }
        x => {
            crypto_bail!("Unable to unwrap key: format not supported for unwrapping: {x:?}")
        }
    }?;

    match key_wrapping_data.get_encoding() {
        EncodingOption::TTLVEncoding => {
            // For TTLV encoding, convert the plaintext to a KeyValue using TTLV parsing
            KeyValue::from_ttlv_bytes(plaintext.as_bytes(), key_format_type).map_err(Into::into)
        }
        EncodingOption::NoEncoding => {
            match key_format_type {
                KeyFormatType::Raw
                | KeyFormatType::ECPrivateKey
                | KeyFormatType::Opaque
                | KeyFormatType::PKCS1
                | KeyFormatType::PKCS10
                | KeyFormatType::PKCS12
                | KeyFormatType::PKCS7
                | KeyFormatType::PKCS8
                | KeyFormatType::Pkcs12Legacy
                | KeyFormatType::X509
                | KeyFormatType::CoverCryptSecretKey
                | KeyFormatType::CoverCryptPublicKey => {
                    // For no encoding, create a structure with the plaintext as bytes
                    let key_material = KeyMaterial::ByteString(plaintext.to_vec().into());
                    Ok(KeyValue::Structure {
                        key_material,
                        attributes: Some(Attributes::default()),
                    })
                }
                KeyFormatType::TransparentSymmetricKey => {
                    // For no encoding, create a structure with the plaintext as bytes
                    let key_material = KeyMaterial::TransparentSymmetricKey {
                        key: plaintext.to_vec().into(),
                    };
                    Ok(KeyValue::Structure {
                        key_material,
                        attributes: Some(Attributes::default()),
                    })
                }

                f => {
                    crypto_bail!("Unable to unwrap key: format not supported for unwrapping: {f:?}")
                }
            }
        }
    }
}

/// Unwrap a key using a symmetric key
///
/// # Arguments
/// * `key_wrapping_data` - the key wrapping data
/// * `ciphertext` - the ciphertext to unwrap
/// * `aad` - the additional authenticated data
/// * `unwrapping_key_block` - the unwrapping key block
///
/// # Returns
/// * `KResult<Vec<u8>>` - the unwrapped key bytes (which may be TTLV Encoded)
fn unwrap_with_symmetric_key(
    key_wrapping_data: &KeyWrappingData,
    ciphertext: &[u8],
    unwrapping_key_block: &KeyBlock,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Extract the block cipher mode from the key wrapping data
    let block_cipher_mode = key_wrapping_data
        .encryption_key_information
        .clone()
        .and_then(|information| information.cryptographic_parameters)
        .and_then(|parameters| parameters.block_cipher_mode);

    // Extract the wrapping key bytes from the unwrapping key block
    let unwrap_secret = unwrapping_key_block
        .key_bytes()
        .context("unwrapping key bytes:")?;

    // If not AES GCM, unwrap using RFC 5649 (a.k.a NIST Key Wrap)
    if block_cipher_mode == Some(BlockCipherMode::GCM) {
        aes_gcm_unwrap(ciphertext, &unwrap_secret)
    } else {
        // unwrap using rfc_5649
        rfc5649_unwrap(ciphertext, &unwrap_secret)
    }
}

/// Unwrap a key using AES GCM
///
/// # Arguments
/// * `ciphertext` - the ciphertext to unwrap
/// * `aad` - the additional authenticated data
/// * `unwrap_secret` - the unwrapping key
///
/// # Returns
/// * `KResult<Vec<u8>>` - the unwrapped key
fn aes_gcm_unwrap(
    ciphertext: &[u8],
    unwrap_secret: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // unwrap using aes Gcm
    let len = ciphertext.len();
    if len < TAG_LENGTH + NONCE_LENGTH {
        crypto_bail!("Invalid wrapped key - insufficient length.");
    }
    let aead = SymCipher::Aes256Gcm;
    let nonce = ciphertext
        .get(..NONCE_LENGTH)
        .ok_or_else(|| CryptoError::IndexingSlicing("unwrap: nonce".to_owned()))?;
    let wrapped_key_bytes = ciphertext
        .get(NONCE_LENGTH..len - TAG_LENGTH)
        .ok_or_else(|| CryptoError::IndexingSlicing("unwrap: wrapped_key_bytes".to_owned()))?;
    let tag = ciphertext
        .get(len - TAG_LENGTH..)
        .ok_or_else(|| CryptoError::IndexingSlicing("unwrap: tag".to_owned()))?;
    decrypt(aead, unwrap_secret, nonce, &[], wrapped_key_bytes, tag)
}

/// Unwrap a key using a private key
///
/// # Arguments
/// * `private_key` - the private key to use for unwrapping
/// * `key_wrapping_data` - the key wrapping data
/// * `ciphertext` - the ciphertext to unwrap
///
/// # Returns
/// * `KResult<Vec<u8>>` - the unwrapped key
///
/// # Errors
/// * If the private key is not a valid key
/// * If the key wrapping data is not valid
/// * If the ciphertext is not valid
/// * If the unwrapping fails
fn unwrap_with_private_key(
    private_key: &PKey<Private>,
    key_wrapping_data: &KeyWrappingData,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match private_key.id() {
        Id::RSA => unwrap_with_rsa(private_key, key_wrapping_data, ciphertext),
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(private_key, ciphertext),
        other => {
            crypto_bail!(
                "Unable to wrap key: wrapping public key type not supported: {:?}",
                other
            )
        }
    }
}

/// Unwrap a key using RSA OAEP or `PKCS1v15` or RSA AES key wrap
///
/// # Arguments
/// * `private_key` - the private key to use for unwrapping
/// * `key_wrapping_data` - the key wrapping data
/// * `wrapped_key` - the wrapped key to unwrap
/// # Returns
/// * `KResult<Vec<u8>>` - the unwrapped key
///
/// # Errors
/// * If the private key is not a valid key
/// * If the key wrapping data is not valid
/// * If the wrapped key is not valid
/// * If the unwrapping fails
fn unwrap_with_rsa(
    private_key: &PKey<Private>,
    key_wrapping_data: &KeyWrappingData,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (algorithm, padding, hashing_fn) = rsa_parameters(key_wrapping_data);
    match algorithm {
        CryptographicAlgorithm::RSA => match padding {
            PaddingMethod::None => ckm_rsa_aes_key_unwrap(private_key, hashing_fn, wrapped_key),
            PaddingMethod::OAEP => {
                ckm_rsa_pkcs_oaep_key_unwrap(private_key, hashing_fn, wrapped_key)
            }
            #[cfg(not(feature = "fips"))]
            PaddingMethod::PKCS1v15 => ckm_rsa_pkcs_key_unwrap(private_key, wrapped_key),
            _ => crypto_bail!(
                "Unable to unwrap key with RSA: padding method not supported: {padding:?}"
            ),
        },
        x => {
            crypto_bail!(
                "Unable to unwrap key with RSA: algorithm not supported for unwrapping: {:?}",
                x
            )
        }
    }
}

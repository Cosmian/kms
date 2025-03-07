use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
    kmip_objects::Object,
    kmip_types::{
        BlockCipherMode, CryptographicAlgorithm, CryptographicUsageMask, EncodingOption,
        KeyFormatType, PaddingMethod, WrappingMethod,
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
    // Extract authenticated additional data on attributes if exist
    let aad = object_key_block.attributes_mut()?.remove_aad();

    // check that the key wrapping data is present
    let key_wrapping_data = object_key_block
        .key_wrapping_data
        .as_ref()
        .context("unable to unwrap key: key wrapping data is missing")?;

    let wrapped_key = recover_wrapped_key(object_key_block, key_wrapping_data)?;

    let plaintext = unwrap(
        unwrapping_key,
        key_wrapping_data,
        wrapped_key.key_bytes.as_ref(),
        aad.as_deref(),
    )?;

    update_key_block_with_unwrapped_key(
        object_key_block,
        &wrapped_key.attributes,
        wrapped_key.encoding,
        &plaintext,
    )?;

    Ok(())
}

pub struct WrappedKey {
    pub key_bytes: Zeroizing<Vec<u8>>,
    pub attributes: Option<Attributes>,
    pub encoding: EncodingOption,
}

/// Recover the wrapped key from the key block and key wrapping data
/// # Arguments
/// * `object_key_block` - the key block of the object to unwrap
/// * `key_wrapping_data` - the key wrapping data
/// # Returns
/// * `KResult<(Vec<u8>, Option<Attributes>, EncodingOption)>` - the recovered wrapped key, attributes, and encoding
///
pub fn recover_wrapped_key(
    object_key_block: &KeyBlock,
    key_wrapping_data: &KeyWrappingData,
) -> Result<WrappedKey, CryptoError> {
    // check that the wrapping method is supported
    if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
        crypto_bail!("unable to unwrap key: only the Encrypt unwrapping method is supported")
    }

    let encoding = key_wrapping_data.get_encoding();
    Ok(match encoding {
        EncodingOption::TTLVEncoding => WrappedKey {
            key_bytes: object_key_block.key_bytes()?,
            attributes: object_key_block.attributes().ok().cloned(),
            encoding,
        },
        EncodingOption::NoEncoding => {
            let (bytes, attributes) = object_key_block.key_bytes_and_attributes()?;
            WrappedKey {
                key_bytes: bytes,
                attributes: attributes.cloned(),
                encoding,
            }
        }
    })
}

/// Update the key block with the unwrapped key
/// # Arguments
/// * `object_key_block` - the key block of the object to update
/// * `attributes` - the attributes of the key
/// * `encoding` - the encoding of the key
/// * `plaintext` - the unwrapped key
pub fn update_key_block_with_unwrapped_key(
    object_key_block: &mut KeyBlock,
    attributes: &Option<Attributes>,
    encoding: EncodingOption,
    plaintext: &Zeroizing<Vec<u8>>,
) -> Result<(), CryptoError> {
    // unwrap the key based on the encoding
    let key_value: KeyValue = match encoding {
        EncodingOption::TTLVEncoding => serde_json::from_slice::<KeyValue>(plaintext.as_bytes())?,
        EncodingOption::NoEncoding => {
            let key_material: KeyMaterial = match object_key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => KeyMaterial::TransparentSymmetricKey {
                    key: plaintext.to_vec().into(),
                },
                _ => KeyMaterial::ByteString(plaintext.to_vec().into()),
            };
            KeyValue {
                key_material,
                attributes: attributes.clone(),
            }
        }
    };
    // update the object with the unwrapped key value, and remove the wrapping data
    object_key_block.key_value = Some(key_value);
    object_key_block.key_wrapping_data = None;
    // we assume that the key_block KeyFormatType is valid
    Ok(())
}

/// Decrypt bytes using the unwrapping key
pub(crate) fn unwrap(
    unwrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
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
            let block_cipher_mode = key_wrapping_data
                .encryption_key_information
                .clone()
                .and_then(|information| information.cryptographic_parameters)
                .and_then(|parameters| parameters.block_cipher_mode);
            let unwrap_secret = unwrapping_key_block.key_bytes()?;

            if block_cipher_mode == Some(BlockCipherMode::GCM) {
                // unwrap using aes Gcm
                let len = ciphertext.len();
                if len < TAG_LENGTH + NONCE_LENGTH {
                    crypto_bail!("Invalid wrapped key - insufficient length.");
                }
                let aead = SymCipher::Aes256Gcm;
                let nonce = ciphertext
                    .get(..NONCE_LENGTH)
                    .ok_or_else(|| CryptoError::IndexingSlicing("unwrap: nonce".to_owned()))?;
                let wrapped_key_bytes =
                    ciphertext
                        .get(NONCE_LENGTH..len - TAG_LENGTH)
                        .ok_or_else(|| {
                            CryptoError::IndexingSlicing("unwrap: wrapped_key_bytes".to_owned())
                        })?;
                let tag = ciphertext
                    .get(len - TAG_LENGTH..)
                    .ok_or_else(|| CryptoError::IndexingSlicing("unwrap: tag".to_owned()))?;
                let authenticated_data = aad.unwrap_or_default();
                let plaintext = decrypt(
                    aead,
                    &unwrap_secret,
                    nonce,
                    authenticated_data,
                    wrapped_key_bytes,
                    tag,
                )?;
                Ok(plaintext)
            } else {
                // unwrap using rfc_5649
                let plaintext = rfc5649_unwrap(ciphertext, &unwrap_secret)?;
                Ok(plaintext)
            }
        }
        KeyFormatType::TransparentECPrivateKey | KeyFormatType::TransparentRSAPrivateKey => {
            // convert to an openssl private key
            let p_key = kmip_private_key_to_openssl(unwrapping_key)?;
            unwrap_with_private_key(&p_key, key_wrapping_data, ciphertext)
        }
        KeyFormatType::PKCS8 => {
            let p_key = PKey::private_key_from_der(&unwrapping_key_block.key_bytes()?)?;
            unwrap_with_private_key(&p_key, key_wrapping_data, ciphertext)
        }
        x => {
            crypto_bail!("Unable to unwrap key: format not supported for unwrapping: {x:?}")
        }
    }?;
    Ok(plaintext)
}

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

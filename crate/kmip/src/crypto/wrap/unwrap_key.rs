use openssl::pkey::{Id, PKey, Private};
use tracing::debug;
use zeroize::Zeroizing;

use super::WRAPPING_SECRET_LENGTH;
#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::ecies::ecies_decrypt;
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
    error::{result::KmipResultHelper, KmipError},
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::Object,
        kmip_operations::ErrorReason,
        kmip_types::{
            BlockCipherMode, CryptographicAlgorithm, CryptographicUsageMask, EncodingOption,
            KeyFormatType, PaddingMethod, WrappingMethod,
        },
    },
    kmip_bail,
    openssl::kmip_private_key_to_openssl,
};

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

/// Unwrap a key using a password
pub fn unwrap_key_bytes(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    key: &[u8],
    wrapping_password: &str,
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(salt, wrapping_password.as_bytes())?;
    rfc5649_unwrap(key, wrapping_secret.as_ref()).map_err(|e| KmipError::Default(e.to_string()))
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
) -> Result<(), KmipError> {
    // Extract authenticated additional data on attributes if exist
    let aad = object_key_block.attributes_mut()?.remove_aad();

    // check that the key wrapping data is present
    let key_wrapping_data = object_key_block
        .key_wrapping_data
        .as_ref()
        .context("unable to unwrap key: key wrapping data is missing")?;

    // check that the wrapping method is supported
    if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
        kmip_bail!("unable to unwrap key: only the Encrypt unwrapping method is supported")
    }

    // get the encoding
    let encoding = key_wrapping_data
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);

    // unwrap the key based on the encoding
    let key_value: KeyValue = match encoding {
        EncodingOption::TTLVEncoding => {
            let ciphertext = object_key_block.key_bytes()?;
            let plaintext = unwrap(
                unwrapping_key,
                key_wrapping_data,
                ciphertext.as_slice(),
                aad.as_deref(),
            )?;
            serde_json::from_slice::<KeyValue>(&plaintext)?
        }
        EncodingOption::NoEncoding => {
            let (ciphertext, attributes) = object_key_block.key_bytes_and_attributes()?;
            let plain_text = unwrap(
                unwrapping_key,
                key_wrapping_data,
                &ciphertext,
                aad.as_deref(),
            )?;
            let key_material: KeyMaterial = match object_key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => KeyMaterial::TransparentSymmetricKey {
                    key: plain_text.to_vec().into(),
                },
                _ => KeyMaterial::ByteString(plain_text.to_vec().into()),
            };
            KeyValue {
                key_material,
                attributes: attributes.map(|a| Box::new(a.clone())),
            }
        }
    };
    // update the object with the unwrapped key value, and remove the wrapping data
    object_key_block.key_value = key_value;
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
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    debug!(
        "decrypt_bytes: with object: {} on ciphertext length: {}",
        unwrapping_key,
        ciphertext.len()
    );

    // Make sure that the key used to unwrap can be used to unwrap.
    if !unwrapping_key
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::UnwrapKey)?
    {
        return Err(KmipError::InvalidKmipValue(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for UnwrapKey".to_owned(),
        ))
    }

    let unwrapping_key_block = unwrapping_key
        .key_block()
        .context("Unable to unwrap: unwrapping key is not a key")?;
    // unwrap the unwrapping key if necessary
    if unwrapping_key_block.key_wrapping_data.is_some() {
        kmip_bail!("unable to unwrap key: unwrapping key is wrapped and that is not supported")
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
                    kmip_bail!("Invalid wrapped key - insufficient length.");
                }
                let aead = SymCipher::Aes256Gcm;
                let nonce = ciphertext
                    .get(..NONCE_LENGTH)
                    .ok_or_else(|| KmipError::IndexingSlicing("unwrap: nonce".to_owned()))?;
                let wrapped_key_bytes =
                    ciphertext
                        .get(NONCE_LENGTH..len - TAG_LENGTH)
                        .ok_or_else(|| {
                            KmipError::IndexingSlicing("unwrap: wrapped_key_bytes".to_owned())
                        })?;
                let tag = ciphertext
                    .get(len - TAG_LENGTH..)
                    .ok_or_else(|| KmipError::IndexingSlicing("unwrap: tag".to_owned()))?;
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
            kmip_bail!("Unable to unwrap key: format not supported for unwrapping: {x:?}")
        }
    }?;
    Ok(plaintext)
}

fn unwrap_with_private_key(
    private_key: &PKey<Private>,
    key_wrapping_data: &KeyWrappingData,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    match private_key.id() {
        Id::RSA => unwrap_with_rsa(private_key, key_wrapping_data, ciphertext),
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(private_key, ciphertext),
        other => {
            kmip_bail!(
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
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let (algorithm, padding, hashing_fn) = rsa_parameters(key_wrapping_data);
    if padding != PaddingMethod::OAEP {
        kmip_bail!(
            "Unable to wrap key with RSA: padding method not supported: {:?}",
            padding
        )
    }
    match algorithm {
        CryptographicAlgorithm::AES => ckm_rsa_aes_key_unwrap(private_key, hashing_fn, wrapped_key),
        CryptographicAlgorithm::RSA => {
            ckm_rsa_pkcs_oaep_key_unwrap(private_key, hashing_fn, wrapped_key)
        }
        x => {
            kmip_bail!(
                "Unable to wrap key with RSA: algorithm not supported for wrapping: {:?}",
                x
            )
        }
    }
}

use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::Object,
        kmip_types::{
            CryptographicAlgorithm, EncodingOption, KeyFormatType, PaddingMethod, WrappingMethod,
        },
    },
    openssl::kmip_private_key_to_openssl,
};
use openssl::pkey::{Id, PKey, Private};
use tracing::debug;
use zeroize::Zeroizing;

#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::ecies::ecies_decrypt;
use crate::{
    crypto::{
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_unwrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap,
        },
        symmetric::rfc5649::rfc5649_unwrap,
        wrap::common::rsa_parameters,
    },
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail,
};

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
) -> Result<(), KmipUtilsError> {
    // check that the key wrapping data is present
    let key_wrapping_data = object_key_block
        .key_wrapping_data
        .as_ref()
        .context("unable to unwrap key: key wrapping data is missing")?;

    // check that the wrapping method is supported
    if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
        kmip_utils_bail!("unable to unwrap key: only the Encrypt unwrapping method is supported")
    }

    // get the encoding
    let encoding = key_wrapping_data
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);

    // unwrap the key based on the encoding
    let key_value: KeyValue = match encoding {
        EncodingOption::TTLVEncoding => {
            let ciphertext = object_key_block.key_bytes()?;
            let plaintext = unwrap(unwrapping_key, key_wrapping_data, ciphertext.as_slice())?;
            serde_json::from_slice::<KeyValue>(&plaintext)?
        }
        EncodingOption::NoEncoding => {
            let (ciphertext, attributes) = object_key_block.key_bytes_and_attributes()?;
            let plain_text = unwrap(unwrapping_key, key_wrapping_data, &ciphertext)?;
            let key_material: KeyMaterial = match object_key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => KeyMaterial::TransparentSymmetricKey {
                    key: plain_text.to_vec().into(),
                },
                _ => KeyMaterial::ByteString(plain_text.to_vec().into()),
            };
            KeyValue {
                key_material,
                attributes: attributes.cloned(),
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
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    debug!(
        "decrypt_bytes: with object: {:?} on ciphertext length: {}",
        unwrapping_key,
        ciphertext.len()
    );

    let unwrapping_key_block = unwrapping_key
        .key_block()
        .context("Unable to unwrap: unwrapping key is not a key")?;
    // unwrap the unwrapping key if necessary
    if unwrapping_key_block.key_wrapping_data.is_some() {
        kmip_utils_bail!(
            "unable to unwrap key: unwrapping key is wrapped and that is not supported"
        )
    }
    let plaintext = match unwrapping_key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey => {
            // unwrap using rfc_5649
            let unwrap_secret = unwrapping_key_block.key_bytes()?;
            let plaintext = rfc5649_unwrap(ciphertext, &unwrap_secret)?;
            Ok(plaintext)
        }
        KeyFormatType::TransparentECPrivateKey | KeyFormatType::TransparentRSAPrivateKey => {
            // convert to an openssl private key
            let p_key = kmip_private_key_to_openssl(unwrapping_key)?;
            unwrap_with_private_key(p_key, key_wrapping_data, ciphertext)
        }
        KeyFormatType::PKCS8 => {
            let p_key = PKey::private_key_from_der(&unwrapping_key_block.key_bytes()?)?;
            unwrap_with_private_key(p_key, key_wrapping_data, ciphertext)
        }
        x => {
            kmip_utils_bail!(
                "Unable to unwrap key: unwrapping key: format not supported for unwrapping: {x:?}"
            )
        }
    }?;
    Ok(plaintext)
}

fn unwrap_with_private_key(
    private_key: PKey<Private>,
    key_wrapping_data: &KeyWrappingData,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    match private_key.id() {
        Id::RSA => unwrap_with_rsa(private_key, key_wrapping_data, ciphertext),
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(&private_key, ciphertext),
        other => {
            kmip_utils_bail!(
                "Unable to wrap key: wrapping public key type not supported: {other:?}"
            )
        }
    }
}

fn unwrap_with_rsa(
    private_key: PKey<Private>,
    key_wrapping_data: &KeyWrappingData,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let (algorithm, padding, hashing_fn) = rsa_parameters(key_wrapping_data);
    if padding != PaddingMethod::OAEP {
        kmip_utils_bail!("Unable to wrap key with RSA: padding method not supported: {padding:?}")
    }
    match algorithm {
        CryptographicAlgorithm::AES => {
            ckm_rsa_aes_key_unwrap(&private_key, hashing_fn, wrapped_key)
        }
        CryptographicAlgorithm::RSA => {
            ckm_rsa_pkcs_oaep_key_unwrap(&private_key, hashing_fn, wrapped_key)
        }
        x => {
            kmip_utils_bail!(
                "Unable to wrap key with RSA: algorithm not supported for wrapping: {x:?}"
            )
        }
    }
}

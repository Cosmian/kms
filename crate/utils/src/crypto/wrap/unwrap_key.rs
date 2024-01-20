use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptedData},
        kmip_types::{EncodingOption, KeyFormatType, WrappingMethod},
    },
    openssl::kmip_private_key_to_openssl,
};
use openssl::pkey::{PKey, Private};
use tracing::debug;

use crate::{
    crypto::{hybrid_encryption::HybridDecryptionSystem, wrap::rfc_5649_unwrap},
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail, DecryptionSystem,
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
            let plaintext = unwrap(unwrapping_key, ciphertext.as_slice())?;
            serde_json::from_slice::<KeyValue>(&plaintext)?
        }
        EncodingOption::NoEncoding => {
            let (ciphertext, attributes) = object_key_block.key_bytes_and_attributes()?;
            let plain_text = unwrap(unwrapping_key, &ciphertext)?;
            let key_material: KeyMaterial = match object_key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    KeyMaterial::TransparentSymmetricKey { key: plain_text }
                }
                _ => KeyMaterial::ByteString(plain_text),
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
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
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
            let plaintext = rfc_5649_unwrap(ciphertext, &unwrap_secret)?;
            Ok(plaintext)
        }
        KeyFormatType::TransparentECPrivateKey | KeyFormatType::TransparentRSAPrivateKey => {
            // convert to an openssl private key
            let p_key = kmip_private_key_to_openssl(unwrapping_key)?;
            unwrap_with_private_key(p_key, ciphertext)
        }
        KeyFormatType::PKCS8 => {
            let p_key = PKey::private_key_from_der(&unwrapping_key_block.key_bytes()?)?;
            unwrap_with_private_key(p_key, ciphertext)
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
    p_key: PKey<Private>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let decrypt_system = HybridDecryptionSystem::new(None, p_key, true);
    let request = Decrypt {
        data: Some(ciphertext.to_vec()),
        ..Decrypt::default()
    };
    let decrypt_response = decrypt_system.decrypt(&request)?;
    let plaintext = decrypt_response.data.ok_or(KmipUtilsError::Default(
        "Decrypt response does not contain plaintext".to_string(),
    ))?;
    debug!(
        "decrypt_bytes: succeeded: plaintext length: {}",
        plaintext.len()
    );
    let decrypted_data = DecryptedData::try_from(plaintext.as_ref())?;
    Ok(decrypted_data.plaintext)
}

use zeroize::Zeroizing;

use super::{
    encrypt_decrypt::{decrypt_bytes, encrypt_bytes},
    key_unwrap, key_wrap,
};
use crate::{
    crypto::password_derivation::derive_key_from_password,
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::Object,
        kmip_types::{EncodingOption, KeyFormatType, WrappingMethod},
    },
    kmip_bail,
    result::KmipResultHelper as _,
};

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    key_wrap(key, wrapping_secret.as_ref()).map_err(|e| KmipError::Default(e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(
    key: &[u8],
    wrapping_password: &str,
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    key_unwrap(key, wrapping_secret.as_ref()).map_err(|e| KmipError::Default(e.to_string()))
}

/// Wrap a key block with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `rng` - the random number generator
/// * `object_key_block` - the key block of the object to wrap
/// * `wrapping_key` - the wrapping key
/// * `key_wrapping_data` - the key wrapping data
/// # Returns
/// * `KResult<()>` - the result of the operation
pub fn wrap_key_block(
    object_key_block: &mut KeyBlock,
    wrapping_key: &Object,
    key_wrapping_data: Option<KeyWrappingData>,
) -> Result<(), KmipError> {
    let mut key_wrapping_data = key_wrapping_data.unwrap_or_default();

    if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
        kmip_bail!("unable to wrap key: only the Encrypt wrapping method is supported")
    }
    key_wrapping_data.wrapping_method = WrappingMethod::Encrypt;

    let encoding = key_wrapping_data
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);
    key_wrapping_data.encoding_option = Some(encoding);

    // wrap the key based on the encoding
    match encoding {
        EncodingOption::TTLVEncoding => {
            let plaintext = serde_json::to_vec(&object_key_block.key_value)?;
            let ciphertext = encrypt_bytes(wrapping_key, &plaintext)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let plaintext = match &object_key_block.key_value.key_material {
                KeyMaterial::TransparentSymmetricKey { ref key } => key.clone(),
                KeyMaterial::ByteString(ref key) => key.clone(),
                x => kmip_bail!(
                    "unable to wrap key: NoEncoding is not supported for key material: {:?}. Use \
                     TTLVEncoding instead.",
                    x
                ),
            };
            let ciphertext = encrypt_bytes(wrapping_key, &plaintext)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext);
        }
    };
    object_key_block.key_wrapping_data = Some(key_wrapping_data);

    Ok(())
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
            let plaintext = decrypt_bytes(unwrapping_key, ciphertext.as_slice())?;
            serde_json::from_slice::<KeyValue>(&plaintext)?
        }
        EncodingOption::NoEncoding => {
            let (ciphertext, attributes) = object_key_block.key_bytes_and_attributes()?;
            let plain_text = decrypt_bytes(unwrapping_key, &ciphertext)?;
            let key_material: KeyMaterial = match object_key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => KeyMaterial::TransparentSymmetricKey {
                    key: plain_text.to_vec(), // XXX keep zeroizing
                },
                _ => KeyMaterial::ByteString(plain_text.to_vec()), // XXX keep zeroizing
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

#[cfg(test)]
#[cfg(not(feature = "fips"))]
// TODO: create FIPS tests
mod tests {
    use crate::{
        crypto::{
            elliptic_curves::operation::create_x25519_key_pair,
            symmetric::create_symmetric_key_kmip_object,
            wrap::{unwrap_key_block, wrap_key_block},
        },
        error::KmipError,
        kmip::{
            kmip_data_structures::KeyWrappingData,
            kmip_objects::Object,
            kmip_types::{CryptographicAlgorithm, EncodingOption},
        },
    };

    #[test]
    fn test_wrap_unwrap() -> Result<(), KmipError> {
        // the symmetric wrapping key
        let mut sym_wrapping_key_bytes = vec![0; 32];
        openssl::rand::rand_bytes(&mut sym_wrapping_key_bytes).unwrap();
        let sym_wrapping_key = create_symmetric_key_kmip_object(
            sym_wrapping_key_bytes.as_slice(),
            CryptographicAlgorithm::AES,
        );

        // the key to wrap
        let mut sym_key_to_wrap_bytes = vec![0; 32];
        openssl::rand::rand_bytes(&mut sym_key_to_wrap_bytes).unwrap();
        let mut sym_key_to_wrap = create_symmetric_key_kmip_object(
            sym_key_to_wrap_bytes.as_slice(),
            CryptographicAlgorithm::AES,
        );

        let wrapping_key_pair =
            create_x25519_key_pair("wrapping_private_key_uid", "wrapping_public_key_uid")?;
        let mut key_pair_to_wrap =
            create_x25519_key_pair("private_key_to_wrap_uid", "public_key_to_wrap_uid")?;

        // wrap the symmetric key with a symmetric key
        wrap_test(&sym_wrapping_key, &sym_wrapping_key, &mut sym_key_to_wrap)?;
        // wrap the asymmetric key with a symmetric key
        wrap_test(
            &sym_wrapping_key,
            &sym_wrapping_key,
            key_pair_to_wrap.private_key_mut(),
        )?;
        // wrap the symmetric key with an asymmetric key
        wrap_test(
            wrapping_key_pair.public_key(),
            wrapping_key_pair.private_key(),
            &mut sym_key_to_wrap,
        )?;
        // wrap the asymmetric key with an asymmetric key
        wrap_test(
            wrapping_key_pair.public_key(),
            wrapping_key_pair.private_key(),
            key_pair_to_wrap.private_key_mut(),
        )?;
        Ok(())
    }

    fn wrap_test(
        wrapping_key: &Object,
        unwrapping_key: &Object,
        key_to_wrap: &mut Object,
    ) -> Result<(), KmipError> {
        let key_to_wrap_bytes = key_to_wrap.key_block()?.key_bytes()?;

        // no encoding
        {
            // wrap
            wrap_key_block(key_to_wrap.key_block_mut()?, wrapping_key, None)?;
            assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
            assert_eq!(
                key_to_wrap.key_block()?.key_wrapping_data,
                Some(Default::default())
            );
            // unwrap
            unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
            assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
            assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
        }

        // TTLV encoding
        {
            let key_wrapping_data = KeyWrappingData {
                encoding_option: Some(EncodingOption::TTLVEncoding),
                ..Default::default()
            };
            // wrap
            wrap_key_block(
                key_to_wrap.key_block_mut()?,
                wrapping_key,
                Some(key_wrapping_data),
            )?;
            assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
            assert_eq!(
                key_to_wrap.key_block()?.key_wrapping_data,
                Some(KeyWrappingData {
                    encoding_option: Some(EncodingOption::TTLVEncoding),
                    ..Default::default()
                })
            );
            // unwrap
            unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
            assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
            assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
        }

        Ok(())
    }
}

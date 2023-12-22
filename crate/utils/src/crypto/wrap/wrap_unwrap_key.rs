use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
    kmip_objects::Object,
    kmip_types::{EncodingOption, KeyFormatType, WrappingMethod},
};

use crate::{
    crypto::wrap::{decrypt_bytes, encrypt_bytes},
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail,
};

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
) -> Result<(), KmipUtilsError> {
    let mut key_wrapping_data = key_wrapping_data.unwrap_or_default();

    if WrappingMethod::Encrypt != key_wrapping_data.wrapping_method {
        kmip_utils_bail!("unable to wrap key: only the Encrypt wrapping method is supported")
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
                x => kmip_utils_bail!(
                    "unable to wrap key: NoEncoding is not supported for key material: {x:?}. Use \
                     TTLVEncoding instead."
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
            let plaintext = decrypt_bytes(unwrapping_key, ciphertext.as_slice())?;
            serde_json::from_slice::<KeyValue>(&plaintext)?
        }
        EncodingOption::NoEncoding => {
            let (ciphertext, attributes) = object_key_block.key_bytes_and_attributes()?;
            let plain_text = decrypt_bytes(unwrapping_key, &ciphertext)?;
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

#[cfg(test)]
#[cfg(not(feature = "fips"))]
// TODO: create FIPS tests
mod tests {
    use cosmian_kmip::kmip::{
        kmip_data_structures::KeyWrappingData,
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, EncodingOption},
    };

    use crate::{
        crypto::{
            curve_25519::operation::create_x25519_key_pair,
            symmetric::create_symmetric_key,
            wrap::{unwrap_key_block, wrap_key_block},
        },
        error::KmipUtilsError,
    };

    #[test]
    fn test_wrap_unwrap() -> Result<(), KmipUtilsError> {
        // the symmetric wrapping key
        let mut sym_wrapping_key_bytes = vec![0; 32];
        openssl::rand::rand_bytes(&mut sym_wrapping_key_bytes).unwrap();
        let sym_wrapping_key = create_symmetric_key(
            sym_wrapping_key_bytes.as_slice(),
            CryptographicAlgorithm::AES,
        )?;

        // the key to wrap
        let mut sym_key_to_wrap_bytes = vec![0; 32];
        openssl::rand::rand_bytes(&mut sym_key_to_wrap_bytes).unwrap();
        let mut sym_key_to_wrap = create_symmetric_key(
            sym_key_to_wrap_bytes.as_slice(),
            CryptographicAlgorithm::AES,
        )?;

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
    ) -> Result<(), KmipUtilsError> {
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

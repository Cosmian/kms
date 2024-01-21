use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{
            KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
        },
        kmip_objects::Object,
        kmip_operations::Encrypt,
        kmip_types::{EncodingOption, KeyFormatType, WrappingMethod},
    },
    openssl::kmip_public_key_to_openssl,
};
use openssl::pkey::{PKey, Public};
use tracing::debug;

use crate::{
    crypto::{hybrid_encryption::HybridEncryptionSystem, symmetric::rfc5649::rfc5649_wrap},
    error::KmipUtilsError,
    kmip_utils_bail, EncryptionSystem,
};

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
) -> Result<(), KmipUtilsError> {
    if object_key_block.key_wrapping_data.is_some() {
        kmip_utils_bail!("unable to wrap the key: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_specification.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            kmip_utils_bail!("Unable to wrap the key: wrapping method is not supported: {x:?}")
        }
    }

    // determine the encoding of the wrapping
    let encoding = key_wrapping_specification
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);

    let key_wrapping_data = KeyWrappingData {
        wrapping_method: key_wrapping_specification.wrapping_method,
        encryption_key_information: key_wrapping_specification
            .encryption_key_information
            .clone(),
        mac_or_signature_key_information: key_wrapping_specification
            .mac_or_signature_key_information
            .clone(),
        encoding_option: key_wrapping_specification.encoding_option,
        ..KeyWrappingData::default()
    };

    // wrap the key based on the encoding
    // wrap the key based on the encoding
    match encoding {
        EncodingOption::TTLVEncoding => {
            let plaintext = serde_json::to_vec(&object_key_block.key_value)?;
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &plaintext)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let plaintext = object_key_block.key_bytes()?;
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &plaintext)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext);
        }
    };

    object_key_block.key_wrapping_data = Some(key_wrapping_data);

    Ok(())
}

/// Encrypt bytes using the wrapping key
pub(crate) fn wrap(
    wrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    debug!(
        "encrypt_bytes: with object: {:?}",
        wrapping_key.object_type()
    );
    match wrapping_key {
        Object::Certificate {
            certificate_value, ..
        } => {
            // TODO(ECSE): cert should be verified before anything
            //verify_certificate(certificate_value, kms, owner, params).await?;
            debug!("encrypt_bytes: Encryption with certificate: certificate OK");
            let encrypt_system = HybridEncryptionSystem::instantiate_with_certificate(
                "id",
                certificate_value,
                true,
            )?;
            let request = Encrypt {
                data: Some(plaintext.to_vec()),
                ..Encrypt::default()
            };
            let encrypt_response = encrypt_system.encrypt(&request)?;
            let ciphertext = encrypt_response.data.ok_or(KmipUtilsError::Default(
                "Encrypt response does not contain ciphertext".to_string(),
            ))?;
            debug!(
                "encrypt_bytes: succeeded: ciphertext length: {}",
                ciphertext.len()
            );
            Ok(ciphertext)
        }
        Object::PGPKey { key_block, .. }
        | Object::SecretData { key_block, .. }
        | Object::SplitKey { key_block, .. }
        | Object::PrivateKey { key_block }
        | Object::PublicKey { key_block }
        | Object::SymmetricKey { key_block } => {
            // wrap the wrapping key if necessary
            if key_block.key_wrapping_data.is_some() {
                kmip_utils_bail!(
                    "unable to wrap keys: wrapping key is wrapped and that is not supported"
                )
            }
            let ciphertext = match key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    // wrap using rfc_5649
                    let wrap_secret = key_block.key_bytes()?;
                    let ciphertext = rfc5649_wrap(plaintext, &wrap_secret)?;
                    Ok(ciphertext)
                }
                KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentRSAPublicKey => {
                    //convert to transparent key and wrap
                    // note: when moving to full openssl this double conversion will be unnecessary
                    let p_key = kmip_public_key_to_openssl(wrapping_key)?;
                    wrap_with_public_key(p_key, key_wrapping_data, plaintext)
                }
                // this really is SPKI
                KeyFormatType::PKCS8 => {
                    let p_key = PKey::public_key_from_der(&key_block.key_bytes()?)?;
                    wrap_with_public_key(p_key, key_wrapping_data, plaintext)
                }
                x => {
                    kmip_utils_bail!(
                        "Unable to wrap key: wrapping key: key format not supported for wrapping: \
                         {x:?}"
                    )
                }
            }?;
            Ok(ciphertext)
        }
        _ => Err(KmipUtilsError::NotSupported(format!(
            "Wrapping key type not supported: {:?}",
            wrapping_key.object_type()
        ))),
    }
}

fn wrap_with_public_key(
    pubkey: PKey<Public>,
    _key_wrapping_data: &KeyWrappingData,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let request = Encrypt {
        data: Some(plaintext.to_vec()),
        ..Encrypt::default()
    };
    let encrypt_system = HybridEncryptionSystem::new("public_key_uid", pubkey, true);
    let encrypt_response = encrypt_system.encrypt(&request)?;
    let ciphertext = encrypt_response.data.ok_or(KmipUtilsError::Default(
        "Encrypt response does not contain ciphertext".to_string(),
    ))?;
    debug!(
        "encrypt_bytes: succeeded: ciphertext length: {}",
        ciphertext.len()
    );
    Ok(ciphertext)
}

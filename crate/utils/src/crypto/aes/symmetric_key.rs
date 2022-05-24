use std::convert::TryFrom;

use cosmian_crypto_base::{entropy::CsRng, symmetric_crypto::aes_256_gcm_pure::KEY_LENGTH};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType},
    },
};

//TODO: BGR: CsRng should be passed as a param and not instantiated on every call
/// Generate an AES-256 bits symmetric key
/// `cryptographic_length` is a value in bytes
pub fn create_aes_symmetric_key(cryptographic_length: Option<usize>) -> Result<Object, KmipError> {
    let aes_key_len = cryptographic_length.unwrap_or(KEY_LENGTH);
    // Generate symmetric key
    let mut rng = CsRng::default();
    let symmetric_key = rng.generate_random_bytes(aes_key_len);
    let symmetric_key_len = i32::try_from(symmetric_key.len()).map_err(|_e| {
        KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Message,
            "AES: Invalid key len".to_string(),
        )
    })?;

    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::AES,
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::TransparentSymmetricKey { key: symmetric_key },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(symmetric_key_len),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: symmetric_key_len,
            key_wrapping_data: None,
        },
    })
}

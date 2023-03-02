use cosmian_crypto_core::{reexport::rand_core::RngCore, CsRng};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType},
    },
    kmip_bail,
};

use super::KEY_LENGTH;

/// Create a symmetric key for the given algorithm
/// `cryptographic_length` is a value in bits that should be a multiple of 8
pub fn create_symmetric_key(
    rng: &mut CsRng,
    cryptographic_algorithm: CryptographicAlgorithm,
    cryptographic_length: Option<usize>,
) -> Result<Object, KmipError> {
    let key_len = match cryptographic_length {
        Some(bits) => {
            if bits % 8 != 0 {
                kmip_bail!(
                    "The cryptographic length of the symmetric key must be a value in bits which \
                     is a multiple of 8 "
                )
            }
            bits / 8
        }
        None => KEY_LENGTH,
    };

    // Generate symmetric key
    let mut symmetric_key = vec![0; key_len];
    rng.fill_bytes(&mut symmetric_key);
    // this length is in bits
    let symmetric_key_len = key_len as i32 * 8;

    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm,
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey { key: symmetric_key },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(cryptographic_algorithm),
                    cryptographic_length: Some(symmetric_key_len),
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                    ),
                    key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: symmetric_key_len,
            key_wrapping_data: None,
        },
    })
}

use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::Create,
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, VendorAttribute,
    },
};

/// Create a symmetric key for the given algorithm
pub fn create_symmetric_key(
    key_bytes: &[u8],
    cryptographic_algorithm: CryptographicAlgorithm,
) -> Object {
    // this length is in bits
    let symmetric_key_len = key_bytes.len() as i32 * 8;
    //
    Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm,
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: key_bytes.to_vec(),
                },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(cryptographic_algorithm),
                    cryptographic_length: Some(symmetric_key_len),
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt
                            | CryptographicUsageMask::Decrypt
                            | CryptographicUsageMask::WrapKey
                            | CryptographicUsageMask::UnwrapKey
                            | CryptographicUsageMask::KeyAgreement,
                    ),
                    key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: symmetric_key_len,
            key_wrapping_data: None,
        },
    }
}

/// Build a `CreateKeyPairRequest` for a curve 25519 key pair
#[must_use]
pub fn symmetric_key_create_request(
    key_len_in_bits: usize,
    cryptographic_algorithm: CryptographicAlgorithm,
) -> Create {
    Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            activation_date: None,
            cryptographic_algorithm: Some(cryptographic_algorithm),
            cryptographic_length: Some(key_len_in_bits as i32),
            cryptographic_parameters: None,
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt
                    | CryptographicUsageMask::WrapKey
                    | CryptographicUsageMask::UnwrapKey
                    | CryptographicUsageMask::KeyAgreement,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            link: None,
            object_type: ObjectType::SymmetricKey,
            vendor_attributes: None,
            cryptographic_domain_parameters: None,
        },
        protection_storage_masks: None,
    }
}

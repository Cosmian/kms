use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::Create,
    kmip_types::{Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType},
};
use cosmian_kms_utils::tagging::set_tags;

use crate::error::KmsCryptoError;

/// Create a symmetric key for the given algorithm
#[must_use]
pub fn create_symmetric_key_kmip_object(
    key_bytes: &[u8],
    cryptographic_algorithm: CryptographicAlgorithm,
) -> Object {
    // this length is in bits
    let symmetric_key_len = key_bytes.len() as i32 * 8;

    let attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
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
        ..Attributes::default()
    };

    // The default format for a symmetric key is Raw
    //  according to sec. 4.26 Key Format Type of the KMIP 2.1 specs:
    //  see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115585
    // The key created here has a format of TransparentSymmetricKey
    // This is no a problem since when it is exported, it is by default converted to a Raw key
    Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(cryptographic_algorithm),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: key_bytes.to_vec(),
                },
                attributes: Some(attributes),
            },
            cryptographic_length: Some(symmetric_key_len),
            key_wrapping_data: None,
        },
    }
}

/// Build a `CreateKeyPairRequest` for a symmetric key
pub fn symmetric_key_create_request<T: IntoIterator<Item = impl AsRef<str>>>(
    key_len_in_bits: usize,
    cryptographic_algorithm: CryptographicAlgorithm,
    tags: T,
) -> Result<Create, KmsCryptoError> {
    let mut attributes = Attributes {
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
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };
    set_tags(&mut attributes, tags)?;
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    })
}

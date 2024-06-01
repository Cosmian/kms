use zeroize::Zeroizing;

use crate::{
    error::{result::KmipResult, KmipError},
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::Create,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            UniqueIdentifier,
        },
    },
};

/// Create a symmetric key for the given algorithm
pub fn create_symmetric_key_kmip_object(
    key_bytes: &[u8],
    cryptographic_algorithm: CryptographicAlgorithm,
    sensitive: bool,
) -> KmipResult<Object> {
    // this length is in bits
    let cryptographic_length = Some(i32::try_from(key_bytes.len())? * 8);

    let attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        cryptographic_algorithm: Some(cryptographic_algorithm),
        cryptographic_length,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        sensitive,
        ..Attributes::default()
    };

    // The default format for a symmetric key is Raw
    //  according to sec. 4.26 Key Format Type of the KMIP 2.1 specs:
    //  see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115585
    // The key created here has a format of TransparentSymmetricKey
    // This is no a problem since when it is exported, it is by default converted to a Raw key
    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(cryptographic_algorithm),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::from(key_bytes.to_vec()),
                },
                attributes: Some(attributes),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

/// Build a `CreateKeyPairRequest` for a symmetric key
pub fn symmetric_key_create_request<T: IntoIterator<Item = impl AsRef<str>>>(
    key_id: Option<UniqueIdentifier>,
    key_len_in_bits: usize,
    cryptographic_algorithm: CryptographicAlgorithm,
    tags: T,
    sensitive: bool,
    wrap_key_id: Option<&String>,
) -> Result<Create, KmipError> {
    let cryptographic_length = Some(i32::try_from(key_len_in_bits)?);
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(cryptographic_algorithm),
        cryptographic_length,
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
        unique_identifier: key_id,
        sensitive,
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    if let Some(wrap_key_id) = wrap_key_id {
        attributes.set_wrapping_key_id(wrap_key_id);
    }
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    })
}

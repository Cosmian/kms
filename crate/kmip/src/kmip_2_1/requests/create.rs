use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    KmipError,
    kmip_0::kmip_types::{CryptographicUsageMask, SecretDataType},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, SecretData, SymmetricKey},
        kmip_operations::Create,
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
    },
};

/// Create a symmetric key for the given algorithm
pub fn create_symmetric_key_kmip_object(
    key_bytes: &[u8],
    create_attributes: &Attributes,
) -> Result<Object, KmipError> {
    let mut tags = create_attributes.get_tags();
    tags.insert("_kk".to_owned());
    // The cryptographic algorithm must be specified
    let cryptographic_algorithm = create_attributes.cryptographic_algorithm.ok_or_else(|| {
        KmipError::NotSupported(
            "the cryptographic algorithm must be specified for symmetric key creation".to_owned(),
        )
    })?;
    // Generate a new UID if none is provided.
    let uid = match &create_attributes
        .unique_identifier
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
    {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid.to_owned(),
    };
    // this length is in bits
    let cryptographic_length = Some(i32::try_from(key_bytes.len())? * 8);
    let mut attributes = create_attributes.clone();
    attributes.object_type = Some(ObjectType::SymmetricKey);
    attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
    attributes.cryptographic_length = cryptographic_length;
    attributes.cryptographic_usage_mask = Some(
        CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt
            | CryptographicUsageMask::WrapKey
            | CryptographicUsageMask::UnwrapKey
            | CryptographicUsageMask::KeyAgreement,
    );
    attributes.key_format_type = Some(KeyFormatType::TransparentSymmetricKey);
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid));
    // set the tags in the attributes
    attributes.set_tags(tags)?;

    // The default format for a symmetric key is Raw
    //  according to sec. 4.26 Key Format Type of the KMIP 2.1 specs:
    //  see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115585
    // The key created here has a format of TransparentSymmetricKey
    // This is no a problem since when it is exported, it is by default converted to a Raw key
    Ok(Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(cryptographic_algorithm),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::from(key_bytes.to_vec()),
                },
                attributes: Some(attributes),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}

/// Build a `Create` request for a symmetric key
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
        sensitive: if sensitive { Some(true) } else { None },
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

/// Create a secret data for the given type
pub fn create_secret_data_kmip_object(
    secret_bytes: &[u8],
    secret_data_type: SecretDataType,
    create_attributes: &Attributes,
) -> Result<Object, KmipError> {
    let mut tags = create_attributes.get_tags();
    tags.insert("_sd".to_owned());
    // Generate a new UID if none is provided.
    let uid = match &create_attributes
        .unique_identifier
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
    {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid.to_owned(),
    };
    // this length is in bits
    let mut attributes = create_attributes.clone();
    attributes.object_type = Some(ObjectType::SecretData);
    attributes.cryptographic_usage_mask = Some(
        CryptographicUsageMask::DeriveKey
            | CryptographicUsageMask::KeyAgreement
            | CryptographicUsageMask::Authenticate,
    );
    attributes.key_format_type = Some(KeyFormatType::Raw);
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid));
    // set the tags in the attributes
    attributes.set_tags(tags)?;

    Ok(Object::SecretData(SecretData {
        secret_data_type,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(secret_bytes.to_vec())),
                attributes: Some(attributes),
            }),
            key_wrapping_data: None,
            cryptographic_algorithm: None,
            cryptographic_length: None,
        },
    }))
}

/// Build a `Create` request for a secrete data - random Seed of 32 bytes generated server-side
pub fn secret_data_create_request<T: IntoIterator<Item = impl AsRef<str>>>(
    secret_id: Option<UniqueIdentifier>,
    tags: T,
    sensitive: bool,
    wrap_key_id: Option<&String>,
) -> Result<Create, KmipError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: None,
        cryptographic_length: None,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::DeriveKey
                | CryptographicUsageMask::KeyAgreement
                | CryptographicUsageMask::Authenticate,
        ),
        key_format_type: Some(KeyFormatType::Raw),
        object_type: Some(ObjectType::SecretData),
        unique_identifier: secret_id,
        sensitive: if sensitive { Some(true) } else { None },
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    if let Some(wrap_key_id) = wrap_key_id {
        attributes.set_wrapping_key_id(wrap_key_id);
    }
    Ok(Create {
        object_type: ObjectType::SecretData,
        attributes,
        protection_storage_masks: None,
    })
}

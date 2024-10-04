use cloudproof::reexport::cover_crypt::abe_policy::Policy;
use zeroize::Zeroizing;

use super::attributes::{
    access_policy_as_vendor_attribute, policy_as_vendor_attribute,
    rekey_edit_action_as_vendor_attribute, RekeyEditAction,
};
use crate::{
    crypto::wrap::wrap_key_bytes,
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Create, CreateKeyPair, Destroy, Import, Locate, ReKeyKeyPair},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, KeyWrapType,
            Link, LinkType, LinkedObjectIdentifier, UniqueIdentifier, WrappingMethod,
        },
    },
};

/// Build a `CreateKeyPair` request for an `CoverCrypt` Master Key
pub fn build_create_master_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    policy: &Policy,
    tags: T,
) -> Result<CreateKeyPair, KmipError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![policy_as_vendor_attribute(policy)?]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(CreateKeyPair {
        common_attributes: Some(attributes),
        ..CreateKeyPair::default()
    })
}

/// Build a `Create` request for an `CoverCrypt` User Decryption Key
pub fn build_create_user_decryption_private_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_policy: &str,
    cover_crypt_master_private_key_id: &str,
    tags: T,
) -> Result<Create, KmipError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_private_key_id.to_owned(),
            ),
        }]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(Create {
        attributes,
        object_type: ObjectType::PrivateKey,
        protection_storage_masks: None,
    })
}

/// Build a `Import` request for an `CoverCrypt` User Decryption Key
///
/// A unique identifier will be generated if none is supplied
#[allow(clippy::too_many_arguments)]
pub fn build_import_decryption_private_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key: &[u8],
    unique_identifier: Option<String>,
    replace_existing: bool,
    cover_crypt_master_private_key_id: &str,
    access_policy: &str,
    is_wrapped: bool,
    wrapping_password: Option<String>,
    tags: T,
) -> Result<Import, KmipError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_private_key_id.to_owned(),
            ),
        }]),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;

    // The key could be:
    //  - already wrapped (is_wrapped is true)
    //  - to wrap (wrapping_password is some)
    //  - or not wrapped (otherwise)
    let is_wrapped = is_wrapped || wrapping_password.is_some();
    let key = Zeroizing::from(if let Some(wrapping_password) = wrapping_password {
        wrap_key_bytes(private_key, &[0_u8; 16], &wrapping_password)?
    } else {
        private_key.to_vec()
    });

    let cryptographic_length = Some(i32::try_from(private_key.len())? * 8);
    Ok(Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.unwrap_or_default()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(replace_existing),
        // We don't deal with the case we need to unwrapped before storing
        key_wrap_type: if is_wrapped {
            Some(KeyWrapType::AsRegistered)
        } else {
            None
        },
        attributes: attributes.clone(),
        object: Object::PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(key),
                    attributes: Some(Box::new(attributes)),
                },
                cryptographic_length,
                key_wrapping_data: if is_wrapped {
                    Some(Box::new(KeyWrappingData {
                        wrapping_method: WrappingMethod::Encrypt,
                        ..KeyWrappingData::default()
                    }))
                } else {
                    None
                },
            },
        },
    })
}

/// Build a `Import` request for an Cover Crypt Master Private Key
///
/// A unique identifier will be generated if none is supplied
#[allow(clippy::too_many_arguments)]
pub fn build_import_private_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key: &[u8],
    unique_identifier: Option<String>,
    replace_existing: bool,
    cover_crypt_master_public_key_id: &str,
    policy: &Policy,
    is_wrapped: bool,
    wrapping_password: Option<String>,
    tags: T,
) -> Result<Import, KmipError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![policy_as_vendor_attribute(policy)?]),
        link: Some(vec![Link {
            link_type: LinkType::PublicKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_public_key_id.to_owned(),
            ),
        }]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;

    // The key could be:
    //  - already wrapped (is_wrapped is true)
    //  - to wrapped (wrapping_password is some)
    //  - or not wrapped (otherwise)
    let is_wrapped = is_wrapped || wrapping_password.is_some();
    let key = Zeroizing::from(if let Some(wrapping_password) = wrapping_password {
        wrap_key_bytes(private_key, &[0_u8; 16], &wrapping_password)?
    } else {
        private_key.to_vec()
    });

    let cryptographic_length = Some(i32::try_from(private_key.len())? * 8);
    Ok(Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.unwrap_or_default()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(replace_existing),
        key_wrap_type: if is_wrapped {
            Some(KeyWrapType::AsRegistered)
        } else {
            None
        },
        attributes: attributes.clone(),
        object: Object::PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(key),
                    attributes: Some(Box::new(attributes)),
                },
                cryptographic_length,
                key_wrapping_data: if is_wrapped {
                    Some(Box::new(KeyWrappingData {
                        wrapping_method: WrappingMethod::Encrypt,
                        ..KeyWrappingData::default()
                    }))
                } else {
                    None
                },
            },
        },
    })
}

/// Build a `Import` request for an Cover Crypt Master Public Key
///
/// A unique identifier will be generated if none is supplied
pub fn build_import_public_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    public_key: &[u8],
    unique_identifier: Option<String>,
    replace_existing: bool,
    policy: &Policy,
    cover_crypt_master_private_key_id: &str,
    tags: T,
) -> Result<Import, KmipError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PublicKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![policy_as_vendor_attribute(policy)?]),
        link: Some(vec![Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_private_key_id.to_owned(),
            ),
        }]),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;

    let cryptographic_length = Some(i32::try_from(public_key.len())? * 8);
    Ok(Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.unwrap_or_default()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(replace_existing),
        key_wrap_type: None,
        attributes: attributes.clone(),
        object: Object::PublicKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptPublicKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(public_key.to_vec())),
                    attributes: Some(Box::new(attributes)),
                },
                cryptographic_length,
                key_wrapping_data: None,
            },
        },
    })
}

/// Build a `Locate` request to locate an `CoverCrypt` Symmetric Key
pub fn build_locate_symmetric_key_request(access_policy: &str) -> Result<Locate, KmipError> {
    Ok(Locate {
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
            ..Attributes::default()
        },
        ..Locate::default()
    })
}

/// Build a `Revoke` request to locate an `CoverCrypt` User Decryption Key
pub fn build_destroy_key_request(unique_identifier: &str) -> Result<Destroy, KmipError> {
    Ok(Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
    })
}

/// Build a `ReKeyKeyPair` request to locate an `CoverCrypt` User Decryption Key
/// To rekey an attribute of a user decryption key, we first need:
/// - the master private key uid
/// - the `CoverCrypt` attributes to revoke
/// - the `ReKeyKeyPairAction` to perform
///
/// The routine will then locate and renew all user decryption keys with those `CoverCrypt` attributes
pub fn build_rekey_keypair_request(
    master_private_key_unique_identifier: &str,
    action: &RekeyEditAction,
) -> Result<ReKeyKeyPair, KmipError> {
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(
            master_private_key_unique_identifier.to_owned(),
        )),
        private_key_attributes: Some(Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            vendor_attributes: Some(vec![rekey_edit_action_as_vendor_attribute(action)?]),
            ..Attributes::default()
        }),
        ..ReKeyKeyPair::default()
    })
}

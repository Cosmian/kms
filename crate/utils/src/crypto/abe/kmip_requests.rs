use abe_gpsw::core::policy::{AccessPolicy, Attribute, Policy};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{
            Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Import, Locate, ReKeyKeyPair, Revoke,
        },
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, RevocationReason,
        },
    },
};
use serde::{Deserialize, Serialize};

use super::attributes::{
    access_policy_as_vendor_attribute, attributes_as_vendor_attribute, policy_as_vendor_attribute,
};
/// Build a `CreateKeyPair` request for an ABE Master Key
pub fn build_create_master_keypair_request(policy: &Policy) -> Result<CreateKeyPair, KmipError> {
    Ok(CreateKeyPair {
        common_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
            key_format_type: Some(KeyFormatType::AbeMasterSecretKey),
            vendor_attributes: Some(vec![policy_as_vendor_attribute(policy)?]),
            ..Attributes::new(ObjectType::PrivateKey)
        }),
        ..CreateKeyPair::default()
    })
}

/// Build a `CreateKeyPair` request for an ABE User Decryption Key
pub fn build_create_user_decryption_key_pair_request(
    access_policy: &AccessPolicy,
    abe_master_private_key_id: &str,
    abe_master_public_key_id: &str,
) -> Result<CreateKeyPair, KmipError> {
    Ok(CreateKeyPair {
        private_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
            key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
            vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
            link: vec![Link {
                link_type: LinkType::ParentLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    abe_master_private_key_id.to_owned(),
                ),
            }],
            ..Attributes::new(ObjectType::PrivateKey)
        }),
        public_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
            key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
            vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
            link: vec![Link {
                link_type: LinkType::ParentLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    abe_master_public_key_id.to_owned(),
                ),
            }],
            ..Attributes::new(ObjectType::PrivateKey)
        }),
        ..CreateKeyPair::default()
    })
}

/// Build a `Create` request for an ABE User Decryption Key
pub fn build_create_user_decryption_private_key_request(
    access_policy: &AccessPolicy,
    abe_master_private_key_id: &str,
) -> Result<Create, KmipError> {
    Ok(Create {
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
            key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
            vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
            link: vec![Link {
                link_type: LinkType::ParentLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    abe_master_private_key_id.to_owned(),
                ),
            }],
            ..Attributes::new(ObjectType::PrivateKey)
        },
        object_type: ObjectType::PrivateKey,
        protection_storage_masks: None,
    })
}

/// Build a `Import` request for an ABE Master Private Key or an User Decryption
/// Key
///
/// A unique identifier will be generated if none is supplied
pub fn build_import_private_key_request(
    private_key: Object,
    unique_identifier: Option<String>,
    replace_existing: bool,
) -> Result<Import, KmipError> {
    let mut attributes = private_key.key_block()?.key_value.attributes()?.clone();
    attributes.set_object_type(ObjectType::PrivateKey);
    Ok(Import {
        unique_identifier: unique_identifier.unwrap_or_else(|| "".to_owned()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(replace_existing),
        key_wrap_type: None,
        attributes,
        object: private_key,
    })
}

/// Build a `Import` request for an ABE Master Public Key
///
/// A unique identifier will be generated if none is supplied
pub fn build_import_public_key_request(
    public_key: Object,
    unique_identifier: Option<String>,
    replace_existing: bool,
) -> Result<Import, KmipError> {
    Ok(Import {
        unique_identifier: unique_identifier.unwrap_or_else(|| "".to_owned()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(replace_existing),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: public_key,
    })
}

/// Build a `Locate` request to locate an ABE Symmetric Key
pub fn build_locate_symmetric_key_request(
    access_policy: &AccessPolicy,
) -> Result<Locate, KmipError> {
    Ok(Locate {
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            key_format_type: Some(KeyFormatType::AbeSymmetricKey),
            object_type: ObjectType::SymmetricKey,
            vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        ..Locate::new(ObjectType::SymmetricKey)
    })
}

/// Build a `Revoke` request to locate an ABE User Decryption Key
pub fn build_revoke_user_decryption_key_request(
    unique_identifier: &str,
    revocation_reason: RevocationReason,
) -> Result<Revoke, KmipError> {
    Ok(Revoke {
        unique_identifier: Some(unique_identifier.to_string()),
        revocation_reason,
        compromise_occurrence_date: None,
    })
}

/// Build a `Revoke` request to locate an ABE User Decryption Key
pub fn build_destroy_key_request(unique_identifier: &str) -> Result<Destroy, KmipError> {
    Ok(Destroy {
        unique_identifier: Some(unique_identifier.to_string()),
    })
}

/// Build a `ReKeyKeyPair` request to locate an ABE User Decryption Key
/// To rekey an attribute of a user decryption key, we first need:
/// - the master private key uid
/// - the ABE attributes to revoke
/// The routine will then locate and renew all user decryption keys with those ABE attributes
pub fn build_rekey_keypair_request(
    master_private_key_unique_identifier: &str,
    abe_policy_attributes: Vec<abe_gpsw::core::policy::Attribute>,
) -> Result<ReKeyKeyPair, KmipError> {
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(master_private_key_unique_identifier.to_string()),
        private_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
            key_format_type: Some(KeyFormatType::AbeMasterSecretKey),
            vendor_attributes: Some(vec![attributes_as_vendor_attribute(abe_policy_attributes)?]),
            ..Attributes::new(ObjectType::PrivateKey)
        }),
        ..ReKeyKeyPair::default()
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DataToEncrypt {
    pub policy_attributes: Vec<Attribute>,
    #[serde(with = "hex")]
    pub data: Vec<u8>,
}

/// Build an ABE Encryption Request to encrypt the provided `data`
/// with the given `policy attributes` using the public key identified by
/// `public_key_identifier`
pub fn build_hybrid_encryption_request(
    public_key_identifier: &str,
    policy_attributes: Vec<Attribute>,
    resource_uid: Vec<u8>,
    data: Vec<u8>,
) -> Result<Encrypt, serde_json::Error> {
    let data = DataToEncrypt {
        policy_attributes,
        data,
    };
    Ok(Encrypt {
        unique_identifier: Some(public_key_identifier.to_owned()),
        cryptographic_parameters: None,
        data: Some(serde_json::to_vec(&data)?),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: Some(resource_uid),
    })
}

pub fn build_decryption_request(
    user_decryption_key_identifier: &str,
    resource_uid: Vec<u8>,
    encrypted_data: Vec<u8>,
) -> Decrypt {
    Decrypt {
        unique_identifier: Some(user_decryption_key_identifier.to_owned()),
        cryptographic_parameters: None,
        data: Some(encrypted_data),
        iv_counter_nonce: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: Some(resource_uid),
        authenticated_encryption_tag: None,
    }
}

//TODO: BGR: this seems unused - must be revisited _ see issue #192
// /// Build a `Create` request for a Symmetric Key
// pub fn abe_build_create_symmetric_key_request(
//     user_decryption_key_id: &str,
//     access_policy: &AccessPolicy,
//     abe_header_uid: &[u8],
// ) -> KResult<Create> {
//     Ok(Create {
//         object_type: ObjectType::SymmetricKey,
//         attributes: Attributes {
//             cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
//             key_format_type: Some(KeyFormatType::AbeSymmetricKey),
//             object_type: ObjectType::SymmetricKey,
//             vendor_attributes: Some(vec![
//                 access_policy_as_vendor_attribute(access_policy)?,
//                 abe_header_uid_to_vendor_attribute(abe_header_uid),
//             ]),
//             link: vec![Link {
//                 link_type: LinkType::ParentLink,
//                 linked_object_identifier: LinkedObjectIdentifier::TextString(
//                     user_decryption_key_id.to_owned(),
//                 ),
//             }],
//             ..Attributes::new(ObjectType::SymmetricKey)
//         },
//         protection_storage_masks: None,
//     })
// }

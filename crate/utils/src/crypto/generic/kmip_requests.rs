use abe_policy::Attribute;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Decrypt, Encrypt, Import},
    kmip_types::{Attributes, KeyWrapType},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DataToEncrypt {
    pub policy_attributes: Vec<Attribute>,
    #[serde(with = "hex")]
    pub data: Vec<u8>,
}

/// Build an Encryption Request to encrypt the provided `data`
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

/// Build a Decryption Request to decrypt the provided `data`
/// the user key identified by `user_decryption_key_identifier`
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

/// Build a `Import` request for a generic Object
pub fn build_import_object_request(
    object: Object,
    object_type: ObjectType,
    attributes: Attributes,
    unique_identifier: &str,
    replace_existing: Option<bool>,
) -> Import {
    let key_wrap_type = if object.is_wrapped().unwrap_or(false) {
        Some(KeyWrapType::AsRegistered)
    } else {
        None
    };

    // build the import request and run it
    Import {
        unique_identifier: unique_identifier.to_owned(),
        object_type,
        replace_existing,
        key_wrap_type,
        attributes,
        object,
    }
}

use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Decrypt, Encrypt, Import},
    kmip_types::{Attributes, KeyWrapType},
};

/// Build an Encryption Request to encrypt the provided `data`
/// with the given `policy attributes` using the public key identified by
/// `public_key_identifier`
pub fn build_hybrid_encryption_request(
    public_key_identifier: &str,
    access_policy: &str,
    resource_uid: Vec<u8>,
    data: Vec<u8>,
    header_metadata: Option<Vec<u8>>,
) -> Result<Encrypt, std::io::Error> {
    let mut data_to_encrypt = vec![];
    let access_policy_bytes = access_policy.as_bytes();
    leb128::write::unsigned(&mut data_to_encrypt, access_policy_bytes.len() as u64)?;
    data_to_encrypt.extend_from_slice(access_policy_bytes);
    if let Some(header_metadata) = header_metadata {
        leb128::write::unsigned(&mut data_to_encrypt, header_metadata.len() as u64)?;
        data_to_encrypt.extend_from_slice(&header_metadata);
    } else {
        leb128::write::unsigned(&mut data_to_encrypt, 0)?;
    }
    data_to_encrypt.extend_from_slice(&data);

    Ok(Encrypt {
        unique_identifier: Some(public_key_identifier.to_owned()),
        cryptographic_parameters: None,
        data: Some(data_to_encrypt),
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

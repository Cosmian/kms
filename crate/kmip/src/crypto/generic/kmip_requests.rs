use super::data_to_encrypt::DataToEncrypt;
use crate::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Decrypt, Encrypt, ErrorReason, Import, Revoke},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm,
            KeyWrapType, RevocationReason, UniqueIdentifier,
        },
    },
};

/// Build a `Revoke` request to revoke the key identified by `unique_identifier`
pub fn build_revoke_key_request(
    unique_identifier: &str,
    revocation_reason: RevocationReason,
) -> Result<Revoke, KmipError> {
    Ok(Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_string())),
        revocation_reason,
        compromise_occurrence_date: None,
    })
}

/// Build an Encryption Request to encrypt the provided `plaintext`
/// The cryptographic scheme is determined by that of the key identified by `key_unique_identifier`
/// For Covercrypt,
///     - the `encryption_policy` must be provided
///     - a `header_metadata` can be optionally specified
/// For other encryption mechanisms (Elliptic Curves, ...), data to encrypt contains plaintext only
/// The `authentication_data` is optional and can be used to authenticate the encryption
/// for all schemes
pub fn build_encryption_request(
    key_unique_identifier: &str,
    encryption_policy: Option<String>,
    plaintext: Vec<u8>,
    header_metadata: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    cryptographic_algorithm: Option<CryptographicAlgorithm>,
    hashing_algorithm: Option<HashingAlgorithm>,
) -> Result<Encrypt, KmipError> {
    let data_to_encrypt = if encryption_policy.is_some() {
        DataToEncrypt {
            encryption_policy,
            header_metadata,
            plaintext,
        }
        .to_bytes()
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Message, e.to_string()))?
    } else {
        plaintext
    };

    let cryptographic_parameters = cryptographic_algorithm.map(|ca| CryptographicParameters {
        cryptographic_algorithm: Some(ca),
        hashing_algorithm,
        ..Default::default()
    });

    Ok(Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            key_unique_identifier.to_owned(),
        )),
        cryptographic_parameters,
        data: Some(data_to_encrypt),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: authentication_data,
    })
}

/// Build a Decryption Request to decrypt the provided `ciphertext`
/// using the key identified by `key_unique_identifier`
///
/// The `authentication_data` must match the one used for encryption
#[must_use]
pub fn build_decryption_request(
    key_unique_identifier: &str,
    nonce: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    authenticated_tag: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    cryptographic_algorithm: Option<CryptographicAlgorithm>,
    hashing_algorithm: Option<HashingAlgorithm>,
) -> Decrypt {
    let cryptographic_parameters = cryptographic_algorithm.map(|ca| CryptographicParameters {
        cryptographic_algorithm: Some(ca),
        hashing_algorithm,
        ..Default::default()
    });

    Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            key_unique_identifier.to_owned(),
        )),
        cryptographic_parameters,
        data: Some(ciphertext),
        iv_counter_nonce: nonce,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: authentication_data,
        authenticated_encryption_tag: authenticated_tag,
    }
}

/// Build a `Import` request for a generic Object
#[must_use]
pub fn build_import_object_request(
    object: Object,
    object_type: ObjectType,
    attributes: Attributes,
    unique_identifier: &str,
    replace_existing: Option<bool>,
    _key_wrapping_specification: Option<KeyWrappingSpecification>,
) -> Import {
    let key_wrap_type = if object.key_wrapping_data().is_some() {
        Some(KeyWrapType::AsRegistered)
    } else {
        None
    };

    // build the import request and run it
    Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.to_owned()),
        object_type,
        replace_existing,
        key_wrap_type,
        attributes,
        object,
    }
}

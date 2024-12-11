use crate::kmip::{
    kmip_operations::Decrypt,
    kmip_types::{CryptographicParameters, UniqueIdentifier},
};

/// Build a Decryption Request to decrypt the provided `ciphertext`
/// using the key identified by `key_unique_identifier`
///
/// The `authentication_data` must match the one used for encryption
#[must_use]
pub fn decrypt_request(
    key_unique_identifier: &str,
    nonce: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    authenticated_tag: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    cryptographic_parameters: Option<CryptographicParameters>,
) -> Decrypt {
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

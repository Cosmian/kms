use crate::kmip_2_1::{
    kmip_operations::SignatureVerify,
    kmip_types::{CryptographicParameters, UniqueIdentifier},
};

/// Build a Decryption Request to decrypt the provided `ciphertext`
/// using the key identified by `key_unique_identifier`
///
/// The `authentication_data` must match the one used for encryption
#[must_use]
pub fn signature_verify_request(
    key_unique_identifier: &str,
    data: Option<Vec<u8>>,
    digested_data: Option<Vec<u8>>,
    signature_data: Option<Vec<u8>>,
    cryptographic_parameters: Option<CryptographicParameters>,
) -> SignatureVerify {
    SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(
            key_unique_identifier.to_owned(),
        )),
        cryptographic_parameters,
        data,
        digested_data,
        signature_data,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    }
}

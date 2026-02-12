use zeroize::Zeroizing;

use crate::{
    DataToEncrypt, KmipError,
    kmip_2_1::{
        kmip_operations::Encrypt,
        kmip_types::{CryptographicParameters, UniqueIdentifier},
    },
};

/// Build an Encryption Request to encrypt the provided `plaintext`.
///
/// The cryptographic scheme is determined by that of the key identified by `key_unique_identifier`
/// For Covercrypt,
///     - the `encryption_policy` must be provided
///     - a `header_metadata` can be optionally specified
/// For other encryption mechanisms (Elliptic Curves, ...), data to encrypt contains plaintext only
/// The `authentication_data` is optional and can be used to authenticate the encryption
/// for all schemes
pub fn encrypt_request(
    key_unique_identifier: &str,
    encryption_policy: Option<String>,
    plaintext: Vec<u8>,
    nonce: Option<Vec<u8>>,
    authenticated_encryption_additional_data: Option<Vec<u8>>,
    cryptographic_parameters: Option<CryptographicParameters>,
) -> Result<Encrypt, KmipError> {
    let data_to_encrypt = if encryption_policy.is_some() {
        let dte = DataToEncrypt {
            encryption_policy,
            plaintext,
        };

        let bytes = dte.to_bytes()?;
        let dte_ = DataToEncrypt::try_from_bytes(&bytes)?;
        assert_eq!(dte, dte_);
        bytes
    } else {
        plaintext
    };

    Ok(Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            key_unique_identifier.to_owned(),
        )),
        cryptographic_parameters,
        data: Some(Zeroizing::new(data_to_encrypt)),
        i_v_counter_nonce: nonce,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data,
    })
}

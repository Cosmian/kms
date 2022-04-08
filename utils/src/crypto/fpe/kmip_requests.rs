use cosmian_kmip::kmip::kmip_operations::{Decrypt, Encrypt};
use tracing::debug;

use crate::{
    crypto::fpe::operation::{AlphabetCharacters, FpeText},
    result::LibResult,
};

/// Build an FPE Encryption Request to encrypt the provided `data`. Serialize
/// the alphabet used in FPE in the `data` to encrypt
pub fn fpe_build_encryption_request(
    aes_uid: &str,
    tweak: Vec<u8>,
    alphabet_characters: AlphabetCharacters,
    input: &str,
) -> LibResult<Encrypt> {
    let alphabet_and_data = FpeText {
        alphabet_characters,
        input: input.to_string(),
    };
    let alphabet_and_data_serialized = serde_json::to_vec(&alphabet_and_data)?;
    debug!("data serialized: {:?}", alphabet_and_data_serialized);
    Ok(Encrypt {
        unique_identifier: Some(aes_uid.to_owned()),
        cryptographic_parameters: None,
        data: Some(alphabet_and_data_serialized),
        iv_counter_nonce: Some(tweak),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    })
}

/// Build an FPE Encryption Request to decrypt the provided `encrypted_data`.
/// This `encrypted_data` contains the alphabet used in FPE in header.
pub fn fpe_build_decryption_request(
    aes_uid: &str,
    tweak: Vec<u8>,
    encrypted_data: Vec<u8>,
) -> Decrypt {
    Decrypt {
        unique_identifier: Some(aes_uid.to_owned()),
        cryptographic_parameters: None,
        data: Some(encrypted_data),
        iv_counter_nonce: Some(tweak),
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    }
}

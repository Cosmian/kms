use cosmian_crypto_base::symmetric_crypto::ff1::FF1Crypto;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyBlock,
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
    },
};
use serde::{Deserialize, Serialize};

use crate::{kmip_utils::key_bytes_and_attributes_from_key_block, DeCipher, EnCipher};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NumericType {
    U32,
    U64,
    U128,
    // Custom(i32)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AlphabetCharacters {
    Alphabetic,
    SensitiveAlphabetic,
    Numeric(NumericType),
    AlphaNumeric,
    SensitiveAlphaNumeric,
    CustomAlphabet(String),
}

#[derive(Serialize, Deserialize)]
pub struct FpeText {
    pub alphabet_characters: AlphabetCharacters,
    pub input: String,
}

impl FpeText {
    pub fn encrypt(&self, symmetric_key: &[u8], tweak: &[u8]) -> Result<String, KmipError> {
        let ciphertext = match &self.alphabet_characters {
            AlphabetCharacters::Alphabetic => {
                let alphabet = ('a'..='z').collect::<String>();
                FF1Crypto::encrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::SensitiveAlphabetic => {
                let alphabet = ('a'..='z').collect::<String>() + &('A'..='Z').collect::<String>();
                FF1Crypto::encrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::Numeric(numeric_type) => match numeric_type {
                NumericType::U32 => {
                    FF1Crypto::encrypt_digit_string::<u32>(symmetric_key, tweak, &self.input)
                }
                NumericType::U64 => {
                    FF1Crypto::encrypt_digit_string::<u64>(symmetric_key, tweak, &self.input)
                }
                NumericType::U128 => {
                    FF1Crypto::encrypt_digit_string::<u128>(symmetric_key, tweak, &self.input)
                }
            },
            AlphabetCharacters::AlphaNumeric => {
                let alphabet = ('a'..='z').collect::<String>() + &('0'..='9').collect::<String>();
                FF1Crypto::encrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::SensitiveAlphaNumeric => {
                let alphabet = ('a'..='z').collect::<String>()
                    + &('A'..='Z').collect::<String>()
                    + &('0'..='9').collect::<String>();
                FF1Crypto::encrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::CustomAlphabet(alphabet) => {
                FF1Crypto::encrypt_string(symmetric_key, tweak, alphabet, &self.input)
            }
        };
        ciphertext
            .map_err(|e| KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string()))
    }

    pub fn decrypt(&self, symmetric_key: &[u8], tweak: &[u8]) -> Result<String, KmipError> {
        let cleartext = match &self.alphabet_characters {
            AlphabetCharacters::Alphabetic => {
                let alphabet = ('a'..='z').collect::<String>();
                FF1Crypto::decrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::SensitiveAlphabetic => {
                let alphabet = ('a'..='z').collect::<String>() + &('A'..='Z').collect::<String>();
                FF1Crypto::decrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::Numeric(numeric_type) => match numeric_type {
                NumericType::U32 => {
                    FF1Crypto::decrypt_digits_string::<u32>(symmetric_key, tweak, &self.input)
                }
                NumericType::U64 => {
                    FF1Crypto::decrypt_digits_string::<u64>(symmetric_key, tweak, &self.input)
                }
                NumericType::U128 => {
                    FF1Crypto::decrypt_digits_string::<u128>(symmetric_key, tweak, &self.input)
                }
            },
            AlphabetCharacters::AlphaNumeric => {
                let alphabet = ('a'..='z').collect::<String>() + &('0'..='9').collect::<String>();
                FF1Crypto::decrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::SensitiveAlphaNumeric => {
                let alphabet = ('a'..='z').collect::<String>()
                    + &('A'..='Z').collect::<String>()
                    + &('0'..='9').collect::<String>();
                FF1Crypto::decrypt_string(symmetric_key, tweak, &alphabet, &self.input)
            }
            AlphabetCharacters::CustomAlphabet(alphabet) => {
                FF1Crypto::decrypt_string(symmetric_key, tweak, alphabet, &self.input)
            }
        };
        cleartext
            .map_err(|e| KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string()))
    }
}

pub struct FpeCipher {
    key_uid: String,
    symmetric_key: KeyBlock,
}

impl FpeCipher {
    pub fn instantiate(uid: &str, symmetric_key: &Object) -> Result<FpeCipher, KmipError> {
        let key_block = match symmetric_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "Expected a KMIP Symmetric Key".to_owned(),
                ))
            }
        };
        Ok(FpeCipher {
            key_uid: uid.into(),
            symmetric_key: key_block,
        })
    }
}

impl EnCipher for FpeCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let tweak = request
            .iv_counter_nonce
            .as_ref()
            .ok_or_else(|| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Message,
                    "Cannot encrypt without tweak value".to_owned(),
                )
            })?
            .as_slice();

        let data = match &request.data {
            None => None,
            Some(data) => {
                let fpe_text: FpeText = serde_json::from_slice(data).map_err(|e| {
                    KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
                })?;
                let (secret_key, _) =
                    key_bytes_and_attributes_from_key_block(&self.symmetric_key, &self.key_uid)?;
                let ciphertext = fpe_text.encrypt(secret_key, tweak)?;
                let fpe_text_serialized = serde_json::to_vec(&FpeText {
                    alphabet_characters: fpe_text.alphabet_characters,
                    input: ciphertext,
                })
                .map_err(|e| {
                    KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
                })?;
                Some(fpe_text_serialized)
            }
        };
        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data,
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }
}

impl DeCipher for FpeCipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let tweak = request.iv_counter_nonce.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Message,
                "Cannot decrypt without tweak value".to_owned(),
            )
        })?;

        let cleartext = match &request.data {
            None => None,
            Some(data) => {
                let (secret_key, _) =
                    key_bytes_and_attributes_from_key_block(&self.symmetric_key, &self.key_uid)?;
                let fpe_text: FpeText = serde_json::from_slice(data).map_err(|e| {
                    KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
                })?;
                let cleartext = fpe_text.decrypt(secret_key, tweak)?;
                Some(cleartext.as_bytes().to_vec())
            }
        };
        Ok(DecryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: cleartext,
            correlation_value: None,
        })
    }
}

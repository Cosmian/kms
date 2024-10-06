//! AES GCM SIV implementation using aes-gcm-siv crate.
//! Openssl does implement AES GCM SIV, but it is not available in the openssl crate.

use aes_gcm_siv::{AeadInPlace, Aes128GcmSiv, Aes256GcmSiv, Key, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use crate::{
    crypto::symmetric::{AES_128_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_KEY_LENGTH},
    KmipError,
};

/// Encrypt data using AES GCM SIV.
/// # Arguments
/// * `key` - The key to use for encryption.
/// * `nonce` - The nonce to use for encryption.
/// * `aad` - The additional authenticated data.
/// * `plaintext` - The data to encrypt.
/// # Returns
/// * The encrypted data and the tag.
/// # Errors
/// * If the key is not the correct size.
/// * If there is an error encrypting the data.
pub(crate) fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KmipError> {
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = plaintext.to_vec();
    let tag = if key.len() == AES_128_GCM_SIV_KEY_LENGTH {
        Aes128GcmSiv::new(Key::<Aes128GcmSiv>::from_slice(key))
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|e| {
                KmipError::Default(format!("Error encrypting data with AES GCM SIV: {}", e))
            })?
    } else if key.len() == AES_256_GCM_SIV_KEY_LENGTH {
        Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key))
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|e| {
                KmipError::Default(format!("Error encrypting data with AES GCM SIV: {}", e))
            })?
    } else {
        return Err(KmipError::InvalidSize(format!(
            "Invalid key size: {} for AES GCM SIV",
            key.len()
        )));
    };
    Ok((buffer.to_vec(), tag.to_vec()))
}

/// Decrypt data using AES GCM SIV.
/// # Arguments
/// * `key` - The key to use for decryption.
/// * `nonce` - The nonce to use for decryption.
/// * `aad` - The additional authenticated data.
/// * `ciphertext` - The data to decrypt.
/// * `tag` - The tag to use for decryption.
/// # Returns
/// * The decrypted data.
/// # Errors
/// * If the key is not the correct size.
/// * If there is an error decrypting the data.
pub(crate) fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let nonce = Nonce::from_slice(nonce);
    let tag = Tag::from_slice(tag);
    let mut buffer = ciphertext.to_vec();
    if key.len() == AES_128_GCM_SIV_KEY_LENGTH {
        Aes128GcmSiv::new(Key::<Aes128GcmSiv>::from_slice(key))
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
            .map_err(|e| {
                KmipError::Default(format!("Error decrypting data with AES GCM SIV: {}", e))
            })?;
    } else if key.len() == AES_256_GCM_SIV_KEY_LENGTH {
        Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key))
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
            .map_err(|e| {
                KmipError::Default(format!("Error decrypting data with AES GCM SIV: {}", e))
            })?;
    } else {
        return Err(KmipError::InvalidSize(format!(
            "Invalid key size: {} for AES GCM SIV",
            key.len()
        )));
    }
    Ok(Zeroizing::new(buffer.to_vec()))
}

enum UnderLyingCipher {
    Aes128GcmSiv(Aes128GcmSiv),
    Aes256GcmSiv(Aes256GcmSiv),
}

pub struct AesGcmSivStreamCipher {
    cipher: UnderLyingCipher,
}

impl AesGcmSivStreamCipher {
    pub fn new(key: &[u8]) -> Result<Self, KmipError> {
        let cipher = if key.len() == AES_128_GCM_SIV_KEY_LENGTH {
            UnderLyingCipher::Aes128GcmSiv(Aes128GcmSiv::new(Key::<Aes128GcmSiv>::from_slice(key)))
        } else if key.len() == AES_256_GCM_SIV_KEY_LENGTH {
            UnderLyingCipher::Aes256GcmSiv(Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key)))
        } else {
            return Err(KmipError::InvalidSize(format!(
                "Invalid key size: {} for AES GCM SIV",
                key.len()
            )));
        };
        Ok(Self { cipher })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, KmipError> {
        match self.cipher {
            UnderLyingCipher::Aes128GcmSiv(ref mut cipher) => cipher.update(data),
            UnderLyingCipher::Aes256GcmSiv(ref mut cipher) => {
                let mut buffer = data.to_vec();
                cipher
                    .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), &[], &mut buffer)
                    .map_err(|e| {
                        KmipError::Default(format!("Error encrypting data with AES GCM SIV: {}", e))
                    })?;
                Ok(buffer)
            }
        }
    }
}

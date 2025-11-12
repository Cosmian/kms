//! AES GCM SIV implementation using aes-gcm-siv crate.
//! Openssl does implement AES GCM SIV, but it is not available in the openssl crate.

use aes_gcm_siv::{AeadInPlace, Aes128GcmSiv, Aes256GcmSiv, KeyInit};
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    crypto::symmetric::symmetric_ciphers::{
        AES_128_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_KEY_LENGTH,
    },
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
pub(super) fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let nonce = nonce.into();
    let mut buffer = plaintext.to_vec();
    let tag = if key.len() == AES_128_GCM_SIV_KEY_LENGTH {
        Aes128GcmSiv::new(key.into())
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|e| {
                CryptoError::Default(format!("Error encrypting data with AES GCM SIV: {e}"))
            })?
    } else if key.len() == AES_256_GCM_SIV_KEY_LENGTH {
        Aes256GcmSiv::new(key.into())
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|e| {
                CryptoError::Default(format!("Error encrypting data with AES GCM SIV: {e}"))
            })?
    } else {
        return Err(CryptoError::InvalidSize(format!(
            "Invalid key size: {} for AES GCM SIV",
            key.len()
        )));
    };
    Ok((buffer.clone(), tag.to_vec()))
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
pub(super) fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce = nonce.into(); //Nonce::from_slice(nonce);
    let tag = tag.into();
    let mut buffer = ciphertext.to_vec();
    if key.len() == AES_128_GCM_SIV_KEY_LENGTH {
        Aes128GcmSiv::new(key.into())
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
            .map_err(|e| {
                CryptoError::Default(format!("Error decrypting data with AES GCM SIV: {e}"))
            })?;
    } else if key.len() == AES_256_GCM_SIV_KEY_LENGTH {
        Aes256GcmSiv::new(key.into())
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
            .map_err(|e| {
                CryptoError::Default(format!("Error decrypting data with AES GCM SIV: {e}"))
            })?;
    } else {
        return Err(CryptoError::InvalidSize(format!(
            "Invalid key size: {} for AES GCM SIV",
            key.len()
        )));
    }
    Ok(Zeroizing::new(buffer.clone()))
}

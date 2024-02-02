use cosmian_kmip::kmip::kmip_types::{BlockCipherMode, CryptographicAlgorithm};
use openssl::{
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use zeroize::Zeroizing;

use super::{
    AES_128_GCM_IV_LENGTH, AES_128_GCM_KEY_LENGTH, AES_128_GCM_MAC_LENGTH, AES_256_GCM_IV_LENGTH,
    AES_256_GCM_KEY_LENGTH, AES_256_GCM_MAC_LENGTH,
};
use crate::{error::KmipUtilsError, kmip_utils_bail};

#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 tag/mac length in bytes.
pub const CHACHA20_POLY1305_MAC_LENGTH: usize = 16;

/// The supported AEAD ciphers.
#[derive(Debug, Clone, Copy)]
pub enum AeadCipher {
    Aes256Gcm,
    Aes128Gcm,
    #[cfg(not(feature = "fips"))]
    Chacha20Poly1305,
}

impl AeadCipher {
    /// Convert to the corresponding OpenSSL cipher.
    fn to_cipher(self) -> Cipher {
        match self {
            AeadCipher::Aes128Gcm => Cipher::aes_128_gcm(),
            AeadCipher::Aes256Gcm => Cipher::aes_256_gcm(),
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => Cipher::chacha20_poly1305(),
        }
    }

    /// Get the tag size in bytes.
    pub fn tag_size(&self) -> usize {
        match self {
            AeadCipher::Aes128Gcm => AES_128_GCM_MAC_LENGTH,
            AeadCipher::Aes256Gcm => AES_256_GCM_MAC_LENGTH,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => CHACHA20_POLY1305_MAC_LENGTH,
        }
    }

    /// Get the nonce size in bytes.
    pub fn nonce_size(&self) -> usize {
        match self {
            AeadCipher::Aes128Gcm => AES_128_GCM_IV_LENGTH,
            AeadCipher::Aes256Gcm => AES_256_GCM_IV_LENGTH,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => CHACHA20_POLY1305_IV_LENGTH,
        }
    }

    /// Get the key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            AeadCipher::Aes128Gcm => AES_128_GCM_KEY_LENGTH,
            AeadCipher::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => CHACHA20_POLY1305_KEY_LENGTH,
        }
    }

    pub fn from_algorithm_and_key_size(
        algorithm: CryptographicAlgorithm,
        block_cipher_mode: Option<BlockCipherMode>,
        key_size: usize,
    ) -> Result<Self, KmipUtilsError> {
        match algorithm {
            CryptographicAlgorithm::AES => {
                if block_cipher_mode.is_some()
                    && (Some(BlockCipherMode::GCM) != block_cipher_mode
                        || Some(BlockCipherMode::AEAD) != block_cipher_mode)
                {
                    kmip_utils_bail!(KmipUtilsError::NotSupported(
                        "AES is only supported with GCM mode".to_owned()
                    ));
                }
                match key_size {
                    AES_128_GCM_KEY_LENGTH => Ok(AeadCipher::Aes128Gcm),
                    AES_256_GCM_KEY_LENGTH => Ok(AeadCipher::Aes256Gcm),
                    _ => kmip_utils_bail!(KmipUtilsError::NotSupported(
                        "AES key must be 16 or 32 bytes long".to_owned()
                    )),
                }
            }
            #[cfg(not(feature = "fips"))]
            CryptographicAlgorithm::ChaCha20 => {
                if block_cipher_mode.is_some() {
                    kmip_utils_bail!(KmipUtilsError::NotSupported(
                        "ChaCha20 is only supported with Pooly1305. Do not specify the Block \
                         Cipher Mode"
                            .to_owned()
                    ));
                }
                match key_size {
                    32 => Ok(AeadCipher::Chacha20Poly1305),
                    _ => kmip_utils_bail!(KmipUtilsError::NotSupported(
                        "ChaCha20 key must be 32 bytes long".to_owned()
                    )),
                }
            }
            other => kmip_utils_bail!(KmipUtilsError::NotSupported(format!(
                "unsupported cryptographic algorithm: {} for a symmetric key",
                other
            ))),
        }
    }
}

/// Generate a random nonce for the given AEAD cipher.
pub fn random_nonce(aead_cipher: AeadCipher) -> Result<Vec<u8>, KmipUtilsError> {
    let mut nonce = vec![0; aead_cipher.nonce_size()];
    rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key for the given AEAD cipher.
pub fn random_key(aead_cipher: AeadCipher) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let mut key = Zeroizing::from(vec![0; aead_cipher.key_size()]);
    rand_bytes(&mut key)?;
    Ok(key)
}

/// Encrypt the plaintext using the given AEAD cipher, key, nonce and additional
/// authenticated data.
/// Return the ciphertext and the tag.
pub fn aead_encrypt(
    aead_cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KmipUtilsError> {
    // Create buffer for the tag
    let mut tag = vec![0; aead_cipher.tag_size()];
    // Encryption.
    let ciphertext = encrypt_aead(
        aead_cipher.to_cipher(),
        key,
        Some(nonce),
        aad,
        plaintext,
        tag.as_mut(),
    )?;
    Ok((ciphertext, tag))
}

/// Decrypt the ciphertext using the given AEAD cipher, key, nonce and
/// additional authenticated data.
/// Return the plaintext.
pub fn aead_decrypt(
    aead_cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let plaintext = Zeroizing::from(decrypt_aead(
        aead_cipher.to_cipher(),
        key,
        Some(nonce),
        aad,
        ciphertext,
        tag,
    )?);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "fips")]
    use openssl::provider::Provider;
    use openssl::rand::rand_bytes;

    use crate::crypto::symmetric::aead::{
        aead_decrypt, aead_encrypt, random_key, random_nonce, AeadCipher,
    };

    #[test]
    fn test_encrypt_decrypt_aes_gcm_128() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(AeadCipher::Aes128Gcm).unwrap();

        let nonce = random_nonce(AeadCipher::Aes128Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            aead_encrypt(AeadCipher::Aes128Gcm, &key, &nonce, &aad, &message).unwrap();

        let decrypted_data =
            aead_decrypt(AeadCipher::Aes128Gcm, &key, &nonce, &aad, &ciphertext, &tag).unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_256() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(AeadCipher::Aes256Gcm).unwrap();

        let nonce = random_nonce(AeadCipher::Aes256Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            aead_encrypt(AeadCipher::Aes256Gcm, &key, &nonce, &aad, &message).unwrap();

        let decrypted_data =
            aead_decrypt(AeadCipher::Aes256Gcm, &key, &nonce, &aad, &ciphertext, &tag).unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_chacha20_poly1305() {
        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(AeadCipher::Chacha20Poly1305).unwrap();

        let nonce = random_nonce(AeadCipher::Chacha20Poly1305).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            aead_encrypt(AeadCipher::Chacha20Poly1305, &key, &nonce, &aad, &message).unwrap();

        let decrypted_data = aead_decrypt(
            AeadCipher::Chacha20Poly1305,
            key.as_ref(),
            &nonce,
            &aad,
            &ciphertext,
            &tag,
        )
        .unwrap();

<<<<<<< HEAD
        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
=======
        assert_eq!(decrypted_data.as_ref(), message);
>>>>>>> b0b0f652 (rebase fix)
    }
}

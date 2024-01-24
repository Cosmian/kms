use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

use crate::error::KmipUtilsError;

/// The supported AEAD ciphers.
pub enum AeadCipher {
    Aes256Gcm,
    Aes128Gcm,
    #[cfg(not(feature = "fips"))]
    Chacha20Poly1305,
}

impl AeadCipher {
    /// Convert to the corresponding OpenSSL cipher.
    fn to_cipher(&self) -> Cipher {
        match self {
            AeadCipher::Aes256Gcm => Cipher::aes_256_gcm(),
            AeadCipher::Aes128Gcm => Cipher::aes_128_gcm(),
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => Cipher::chacha20_poly1305(),
        }
    }

    /// Get the tag size in bytes.  
    pub fn tag_size(&self) -> usize {
        match self {
            AeadCipher::Aes256Gcm => 16,
            AeadCipher::Aes128Gcm => 16,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => 16,
        }
    }

    /// Get the nonce size in bytes.
    pub fn nonce_size(&self) -> usize {
        match self {
            AeadCipher::Aes256Gcm => 12,
            AeadCipher::Aes128Gcm => 12,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => 12,
        }
    }

    /// Get the key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            AeadCipher::Aes256Gcm => 32,
            AeadCipher::Aes128Gcm => 16,
            #[cfg(not(feature = "fips"))]
            AeadCipher::Chacha20Poly1305 => 32,
        }
    }
}

/// Encrypted data consumed and retuned by the ciphers
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Generate a random nonce for the given AEAD cipher.
pub fn random_nonce(aead_cipher: AeadCipher) -> Result<Vec<u8>, KmipUtilsError> {
    let mut nonce = vec![0; aead_cipher.nonce_size()];
    openssl::rand::rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key for the given AEAD cipher.
pub fn random_key(aead_cipher: AeadCipher) -> Result<Vec<u8>, KmipUtilsError> {
    let mut key = vec![0; aead_cipher.key_size()];
    openssl::rand::rand_bytes(&mut key)?;
    Ok(key)
}

/// Encrypt the plaintext using the given AEAD cipher, key, nonce and additional authenticated data.
/// Return the ciphertext and the tag.
pub fn aead_encrypt(
    aead_cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, KmipUtilsError> {
    // Create buffer for the tag
    let mut tag = vec![0; aead_cipher.tag_size()];
    // Encryption.
    let ciphertext = encrypt_aead(
        aead_cipher.to_cipher(),
        &key,
        Some(nonce),
        aad,
        plaintext,
        tag.as_mut(),
    )?;
    Ok(EncryptedData { ciphertext, tag })
}

/// Decrypt the ciphertext using the given AEAD cipher, key, nonce and additional authenticated data.
/// Return the plaintext.
pub fn aead_decrypt(
    aead_cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    encrypted_data: &EncryptedData,
) -> Result<Vec<u8>, KmipUtilsError> {
    let plaintext = decrypt_aead(
        aead_cipher.to_cipher(),
        key,
        Some(nonce),
        aad,
        encrypted_data.ciphertext.as_slice(),
        encrypted_data.tag.as_slice(),
    )?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use openssl::rand::rand_bytes;
    use zeroize::Zeroizing;

    use crate::crypto::symmetric::aead::{
        aead_decrypt, aead_encrypt, random_key, random_nonce, AeadCipher,
    };

    #[test]
    fn test_encrypt_decrypt_aes_gcm_128() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = Zeroizing::from(random_key(AeadCipher::Aes128Gcm).unwrap());

        let nonce = random_nonce(AeadCipher::Aes128Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let encrypted_data =
            aead_encrypt(AeadCipher::Aes128Gcm, &key, &nonce, &message, &aad).unwrap();

        let decrypted_data =
            aead_decrypt(AeadCipher::Aes128Gcm, &key, &nonce, &aad, &encrypted_data).unwrap();

        assert_eq!(decrypted_data, message);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_256() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = Zeroizing::from(random_key(AeadCipher::Aes256Gcm).unwrap());

        let nonce = random_nonce(AeadCipher::Aes256Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let encrypted_data =
            aead_encrypt(AeadCipher::Aes256Gcm, &key, &nonce, &message, &aad).unwrap();

        let decrypted_data =
            aead_decrypt(AeadCipher::Aes256Gcm, &key, &nonce, &aad, &encrypted_data).unwrap();

        assert_eq!(decrypted_data, message);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_chacha20_poly1305() {
        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = Zeroizing::from(random_key(AeadCipher::Chacha20Poly1305).unwrap());

        let nonce = random_nonce(AeadCipher::Chacha20Poly1305).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let encrypted_data =
            aead_encrypt(AeadCipher::Chacha20Poly1305, &key, &nonce, &message, &aad).unwrap();

        let decrypted_data = aead_decrypt(
            AeadCipher::Chacha20Poly1305,
            &key,
            &nonce,
            &aad,
            &encrypted_data,
        )
        .unwrap();

        assert_eq!(decrypted_data, message);
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    #[cfg(feature = "fips")]
    use openssl::provider::Provider;
    use openssl::rand::rand_bytes;

    use crate::crypto::symmetric::{
        symmetric_ciphers::{decrypt, encrypt, random_key, random_nonce, SymCipher},
        AES_128_GCM_MAC_LENGTH, AES_128_GCM_SIV_MAC_LENGTH, AES_128_XTS_MAC_LENGTH,
        AES_256_XTS_MAC_LENGTH,
    };

    #[test]
    fn test_encrypt_decrypt_aes_gcm_128() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Aes128Gcm).unwrap();

        let nonce = random_nonce(SymCipher::Aes128Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            encrypt(SymCipher::Aes128Gcm, &key, &nonce, &aad, &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_128_GCM_MAC_LENGTH);

        let decrypted_data =
            decrypt(SymCipher::Aes128Gcm, &key, &nonce, &aad, &ciphertext, &tag).unwrap();

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

        let key = random_key(SymCipher::Aes256Gcm).unwrap();

        let nonce = random_nonce(SymCipher::Aes256Gcm).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            encrypt(SymCipher::Aes256Gcm, &key, &nonce, &aad, &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_128_GCM_MAC_LENGTH);

        let decrypted_data =
            decrypt(SymCipher::Aes256Gcm, &key, &nonce, &aad, &ciphertext, &tag).unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[test]
    fn test_encrypt_decrypt_aes_xts_128() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Aes128Xts).unwrap();

        let tweak = random_nonce(SymCipher::Aes128Xts).unwrap();

        let (ciphertext, tag) = encrypt(SymCipher::Aes128Xts, &key, &tweak, &[], &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_128_XTS_MAC_LENGTH); // always 0

        let decrypted_data =
            decrypt(SymCipher::Aes128Xts, &key, &tweak, &[], &ciphertext, &tag).unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[test]
    fn test_encrypt_decrypt_aes_xts_256() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Aes256Xts).unwrap();

        let tweak = random_nonce(SymCipher::Aes256Xts).unwrap();

        let (ciphertext, tag) = encrypt(SymCipher::Aes256Xts, &key, &tweak, &[], &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_256_XTS_MAC_LENGTH); // always 0

        let decrypted_data =
            decrypt(SymCipher::Aes256Xts, &key, &tweak, &[], &ciphertext, &tag).unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_chacha20_poly1305() {
        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Chacha20Poly1305).unwrap();

        let nonce = random_nonce(SymCipher::Chacha20Poly1305).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            encrypt(SymCipher::Chacha20Poly1305, &key, &nonce, &aad, &message).unwrap();

        let decrypted_data = decrypt(
            SymCipher::Chacha20Poly1305,
            key.as_ref(),
            &nonce,
            &aad,
            &ciphertext,
            &tag,
        )
        .unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_aes_gcm_siv_128() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Aes128GcmSiv).unwrap();

        let nonce = random_nonce(SymCipher::Aes128GcmSiv).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            encrypt(SymCipher::Aes128GcmSiv, &key, &nonce, &aad, &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_128_GCM_SIV_MAC_LENGTH);

        let decrypted_data = decrypt(
            SymCipher::Aes128GcmSiv,
            &key,
            &nonce,
            &aad,
            &ciphertext,
            &tag,
        )
        .unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_aes_gcm_siv_256() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mut message = vec![0_u8; 42];
        rand_bytes(&mut message).unwrap();

        let key = random_key(SymCipher::Aes256GcmSiv).unwrap();

        let nonce = random_nonce(SymCipher::Aes256GcmSiv).unwrap();

        let mut aad = vec![0_u8; 24];
        rand_bytes(&mut aad).unwrap();

        let (ciphertext, tag) =
            encrypt(SymCipher::Aes256GcmSiv, &key, &nonce, &aad, &message).unwrap();
        assert_eq!(ciphertext.len(), message.len());
        assert_eq!(tag.len(), AES_128_GCM_SIV_MAC_LENGTH);

        let decrypted_data = decrypt(
            SymCipher::Aes256GcmSiv,
            &key,
            &nonce,
            &aad,
            &ciphertext,
            &tag,
        )
        .unwrap();

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrypted_data.to_vec(), message);
    }
}

#![allow(clippy::unwrap_used)]

#[cfg(feature = "fips")]
use openssl::provider::Provider;
use openssl::rand::rand_bytes;

#[cfg(not(feature = "fips"))]
use crate::crypto::symmetric::symmetric_ciphers::AES_128_GCM_SIV_MAC_LENGTH;
use crate::crypto::symmetric::symmetric_ciphers::{
    decrypt, encrypt, random_key, random_nonce, Mode, SymCipher, AES_128_GCM_MAC_LENGTH,
    AES_128_XTS_MAC_LENGTH, AES_256_GCM_MAC_LENGTH, AES_256_XTS_MAC_LENGTH,
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

    let (ciphertext, tag) = encrypt(SymCipher::Aes128Gcm, &key, &nonce, &aad, &message).unwrap();
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

    let (ciphertext, tag) = encrypt(SymCipher::Aes256Gcm, &key, &nonce, &aad, &message).unwrap();
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

    let (ciphertext, tag) = encrypt(SymCipher::Aes128GcmSiv, &key, &nonce, &aad, &message).unwrap();
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

    let (ciphertext, tag) = encrypt(SymCipher::Aes256GcmSiv, &key, &nonce, &aad, &message).unwrap();
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

#[test]
fn aes_gcm_streaming_test() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    Provider::load(None, "fips").unwrap();

    let mut message1 = vec![0_u8; 42];
    rand_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 29];
    rand_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    rand_bytes(&mut message3).unwrap();

    let key = random_key(SymCipher::Aes256Gcm).unwrap();

    let nonce = random_nonce(SymCipher::Aes256Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    // encrypt
    let mut encryption_cipher = SymCipher::Aes256Gcm
        .stream_cipher(Mode::Encrypt, &key, &nonce, &aad)
        .unwrap();
    let mut result = Vec::<u8>::new();
    result.extend(encryption_cipher.update(&message1).unwrap());
    result.extend(encryption_cipher.update(&message2).unwrap());
    result.extend(encryption_cipher.update(&message3).unwrap());
    let (remainder, tag) = encryption_cipher.finalize_encryption().unwrap();
    result.extend(remainder);
    assert_eq!(
        result.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(tag.len(), AES_256_GCM_MAC_LENGTH);
    // decrypt
    let mut decryption_cipher = SymCipher::Aes256Gcm
        .stream_cipher(Mode::Decrypt, &key, &nonce, &aad)
        .unwrap();
    let mut decrypted_data = decryption_cipher.update(&result).unwrap();
    decrypted_data.extend(decryption_cipher.finalize_decryption(&tag).unwrap());
    assert_eq!(
        decrypted_data.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(
        decrypted_data,
        [&message1[..], &message2[..], &message3[..]].concat()
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn chacha_streaming_test() {
    let mut message1 = vec![0_u8; 42];
    rand_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 29];
    rand_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    rand_bytes(&mut message3).unwrap();

    let key = random_key(SymCipher::Chacha20Poly1305).unwrap();

    let nonce = random_nonce(SymCipher::Chacha20Poly1305).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    // encrypt
    let mut encryption_cipher = SymCipher::Chacha20Poly1305
        .stream_cipher(Mode::Encrypt, &key, &nonce, &aad)
        .unwrap();
    let mut result = Vec::<u8>::new();
    result.extend(encryption_cipher.update(&message1).unwrap());
    result.extend(encryption_cipher.update(&message2).unwrap());
    result.extend(encryption_cipher.update(&message3).unwrap());
    let (remainder, tag) = encryption_cipher.finalize_encryption().unwrap();
    result.extend(remainder);
    assert_eq!(
        result.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(tag.len(), AES_256_GCM_MAC_LENGTH);
    // decrypt
    let mut decryption_cipher = SymCipher::Chacha20Poly1305
        .stream_cipher(Mode::Decrypt, &key, &nonce, &aad)
        .unwrap();
    let mut decrypted_data = decryption_cipher.update(&result).unwrap();
    decrypted_data.extend(decryption_cipher.finalize_decryption(&tag).unwrap());
    assert_eq!(
        decrypted_data.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(
        decrypted_data,
        [&message1[..], &message2[..], &message3[..]].concat()
    );
}

#[test]
fn aes_xts_streaming_test() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    Provider::load(None, "fips").unwrap();

    let mut message1 = vec![0_u8; 42];
    rand_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 27];
    rand_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    rand_bytes(&mut message3).unwrap();

    let key = random_key(SymCipher::Aes256Xts).unwrap();

    let tweak = random_nonce(SymCipher::Aes256Xts).unwrap();

    // encrypt
    let mut encryption_cipher = SymCipher::Aes256Xts
        .stream_cipher(Mode::Encrypt, &key, &tweak, &[])
        .unwrap();
    let mut result = Vec::<u8>::new();
    result.extend(encryption_cipher.update(&message1).unwrap());
    result.extend(encryption_cipher.update(&message2).unwrap());
    result.extend(encryption_cipher.update(&message3).unwrap());
    let (remainder, tag) = encryption_cipher.finalize_encryption().unwrap();
    result.extend(remainder);
    assert_eq!(
        result.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(tag.len(), AES_256_XTS_MAC_LENGTH); //0
    // decrypt
    let mut decryption_cipher = SymCipher::Aes256Xts
        .stream_cipher(Mode::Decrypt, &key, &tweak, &[])
        .unwrap();
    let mut decrypted_data = decryption_cipher.update(&result).unwrap();
    decrypted_data.extend(decryption_cipher.finalize_decryption(&tag).unwrap());
    assert_eq!(
        decrypted_data.len(),
        message1.len() + message2.len() + message3.len()
    );
    assert_eq!(
        decrypted_data,
        [&message1[..], &message2[..], &message3[..]].concat()
    );
}

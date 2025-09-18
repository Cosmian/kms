#![allow(clippy::unwrap_used)]

use cosmian_kmip::kmip_0::kmip_types::PaddingMethod;
use openssl::{provider::Provider, rand::rand_bytes};

#[cfg(feature = "non-fips")]
use crate::crypto::symmetric::symmetric_ciphers::AES_128_GCM_SIV_MAC_LENGTH;
use crate::crypto::symmetric::symmetric_ciphers::{
    AES_128_GCM_MAC_LENGTH, AES_128_XTS_MAC_LENGTH, AES_256_GCM_MAC_LENGTH, AES_256_XTS_MAC_LENGTH,
    Mode, SymCipher, decrypt, encrypt, random_key, random_nonce,
};

#[test]
fn test_encrypt_decrypt_aes_gcm_128() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes128Gcm).unwrap();

    let nonce = random_nonce(SymCipher::Aes128Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes128Gcm, &key, &nonce, &aad, &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_128_GCM_MAC_LENGTH);

    let decrypted_data = decrypt(
        SymCipher::Aes128Gcm,
        &key,
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_gcm_256() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes256Gcm).unwrap();

    let nonce = random_nonce(SymCipher::Aes256Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes256Gcm, &key, &nonce, &aad, &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_128_GCM_MAC_LENGTH);

    let decrypted_data = decrypt(
        SymCipher::Aes256Gcm,
        &key,
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_xts_128() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes128Xts).unwrap();

    let tweak = random_nonce(SymCipher::Aes128Xts).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes128Xts, &key, &tweak, &[], &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_128_XTS_MAC_LENGTH); // always 0

    let decrypted_data = decrypt(
        SymCipher::Aes128Xts,
        &key,
        &tweak,
        &[],
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_xts_256() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes256Xts).unwrap();

    let tweak = random_nonce(SymCipher::Aes256Xts).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes256Xts, &key, &tweak, &[], &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_256_XTS_MAC_LENGTH); // always 0

    let decrypted_data = decrypt(
        SymCipher::Aes256Xts,
        &key,
        &tweak,
        &[],
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_cbc_256_pkcs5_padding() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(cipher).unwrap();
    let iv = random_nonce(cipher).unwrap();

    // By default, when using None padding, PKCS5 padding is used
    let (ciphertext, tag) = encrypt(cipher, &key, &iv, &[], &message, None).unwrap();

    // Let us explicit PKCS5 padding method to decrypt
    let decrypted_data = decrypt(
        SymCipher::Aes256Cbc,
        &key,
        &iv,
        &[],
        &ciphertext,
        &tag,
        Some(PaddingMethod::PKCS5),
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_cbc_256_no_padding() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 32];
    rand_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(cipher).unwrap();
    let iv = random_nonce(cipher).unwrap();
    let padding_method = Some(PaddingMethod::None);

    let (ciphertext, tag) = encrypt(cipher, &key, &iv, &[], &message, padding_method).unwrap();

    let decrypted_data = decrypt(
        SymCipher::Aes256Cbc,
        &key,
        &iv,
        &[],
        &ciphertext,
        &tag,
        padding_method,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn test_encrypt_decrypt_aes_cbc_256_pkcs5_invalid_padding() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 32];
    rand_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(cipher).unwrap();
    let iv = random_nonce(cipher).unwrap();

    for method in [
        PaddingMethod::OAEP,
        PaddingMethod::SSL3,
        PaddingMethod::Zeros,
        PaddingMethod::ANSI_X923,
        PaddingMethod::ISO10126,
        PaddingMethod::PKCS1v15,
        PaddingMethod::X931,
        PaddingMethod::PSS,
    ] {
        encrypt(cipher, &key, &iv, &[], &message, Some(method)).unwrap_err();
    }
}

#[cfg(feature = "non-fips")]
#[test]
fn test_encrypt_decrypt_chacha20_poly1305() {
    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Chacha20Poly1305).unwrap();

    let nonce = random_nonce(SymCipher::Chacha20Poly1305).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    let (ciphertext, tag) = encrypt(
        SymCipher::Chacha20Poly1305,
        &key,
        &nonce,
        &aad,
        &message,
        None,
    )
    .unwrap();

    let decrypted_data = decrypt(
        SymCipher::Chacha20Poly1305,
        key.as_ref(),
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[cfg(feature = "non-fips")]
#[test]
fn test_encrypt_decrypt_aes_gcm_siv_128() {
    // Load FIPS provider module from OpenSSL.
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes128GcmSiv).unwrap();

    let nonce = random_nonce(SymCipher::Aes128GcmSiv).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes128GcmSiv, &key, &nonce, &aad, &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_128_GCM_SIV_MAC_LENGTH);

    let decrypted_data = decrypt(
        SymCipher::Aes128GcmSiv,
        &key,
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[cfg(feature = "non-fips")]
#[test]
fn test_encrypt_decrypt_aes_gcm_siv_256() {
    // Load FIPS provider module from OpenSSL.
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    rand_bytes(&mut message).unwrap();

    let key = random_key(SymCipher::Aes256GcmSiv).unwrap();

    let nonce = random_nonce(SymCipher::Aes256GcmSiv).unwrap();

    let mut aad = vec![0_u8; 24];
    rand_bytes(&mut aad).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes256GcmSiv, &key, &nonce, &aad, &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), AES_128_GCM_SIV_MAC_LENGTH);

    let decrypted_data = decrypt(
        SymCipher::Aes256GcmSiv,
        &key,
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        None,
    )
    .unwrap();

    assert_eq!(decrypted_data.to_vec(), message);
}

#[test]
fn aes_gcm_streaming_test() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
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
        [(&*message1), (&*message2), (&*message3)].concat()
    );
}

#[cfg(feature = "non-fips")]
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
        [(&*message1), (&*message2), (&*message3)].concat()
    );
}

#[test]
fn aes_xts_streaming_test() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
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
        [(&*message1), (&*message2), (&*message3)].concat()
    );
}

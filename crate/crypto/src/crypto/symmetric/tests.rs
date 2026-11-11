use cosmian_kmip::kmip_0::kmip_types::PaddingMethod;
use openssl::provider::Provider;

#[cfg(feature = "non-fips")]
use crate::crypto::symmetric::symmetric_ciphers::AES_128_GCM_SIV_MAC_LENGTH;
use crate::crypto::{
    KmsRng,
    symmetric::symmetric_ciphers::{
        AES_128_GCM_MAC_LENGTH, AES_256_GCM_MAC_LENGTH, Mode, SymCipher, decrypt, encrypt,
        random_key, random_nonce,
    },
};

#[test]
fn test_encrypt_decrypt_aes_gcm_128() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes128Gcm).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Aes128Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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

/// Decrypt with the tag truncated to `len` bytes: `[single-part, streaming]` results.
fn decrypt_truncated(cipher: SymCipher, len: usize) -> [Result<Vec<u8>, crate::CryptoError>; 2] {
    let key = random_key(&KmsRng::new(), cipher).unwrap();
    let nonce = random_nonce(&KmsRng::new(), cipher).unwrap();
    let (ciphertext, mut tag) = encrypt(cipher, &key, &nonce, b"aad", b"message", None).unwrap();
    tag.truncate(len);
    let single = decrypt(cipher, &key, &nonce, b"aad", &ciphertext, &tag, None).map(|p| p.to_vec());
    let mut stream = cipher
        .stream_cipher(Mode::Decrypt, &key, &nonce, b"aad")
        .unwrap();
    let mut streamed = stream.update(&ciphertext).unwrap();
    let tail = stream.finalize_decryption(&tag).map(|t| {
        streamed.extend(t);
        streamed
    });
    [single, tail]
}

fn assert_short_tags_rejected(cipher: SymCipher) {
    for len in [1, 4, 8, 11] {
        for result in decrypt_truncated(cipher, len) {
            assert!(
                matches!(result, Err(crate::CryptoError::InvalidTag(_))),
                "{len}"
            );
        }
    }
}

#[test]
fn test_gcm_rejects_short_tags() {
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();
    assert_short_tags_rejected(SymCipher::Aes256Gcm);
    for len in 12..=16 {
        for result in decrypt_truncated(SymCipher::Aes128Gcm, len) {
            assert_eq!(result.unwrap(), b"message");
        }
    }
}

#[cfg(feature = "non-fips")]
#[test]
fn test_chacha20_poly1305_rejects_short_tags() {
    assert_short_tags_rejected(SymCipher::Chacha20Poly1305);
}

#[test]
fn test_encrypt_decrypt_aes_gcm_256() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips").unwrap();

    let mut message = vec![0_u8; 42];
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes256Gcm).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Aes256Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes128Xts).unwrap();

    let tweak = random_nonce(&KmsRng::new(), SymCipher::Aes128Xts).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes128Xts, &key, &tweak, &[], &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), 0); // XTS has no tag

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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes256Xts).unwrap();

    let tweak = random_nonce(&KmsRng::new(), SymCipher::Aes256Xts).unwrap();

    let (ciphertext, tag) =
        encrypt(SymCipher::Aes256Xts, &key, &tweak, &[], &message, None).unwrap();
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(tag.len(), 0); // XTS has no tag

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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(&KmsRng::new(), cipher).unwrap();
    let iv = random_nonce(&KmsRng::new(), cipher).unwrap();

    // By default, when using None padding, PKCS5 padding is used
    let (ciphertext, tag) = encrypt(cipher, &key, &iv, &[], &message, None).unwrap();
    assert_eq!(tag.len(), 0); // CBC has no tag

    // Let us explicit PKCS5 padding method to decrypt
    let decrypted_data = decrypt(
        cipher,
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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(&KmsRng::new(), cipher).unwrap();
    let iv = random_nonce(&KmsRng::new(), cipher).unwrap();
    let padding_method = Some(PaddingMethod::None);

    let (ciphertext, tag) = encrypt(cipher, &key, &iv, &[], &message, padding_method).unwrap();
    assert_eq!(tag.len(), 0); // CBC has no tag

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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let cipher = SymCipher::Aes256Cbc;
    let key = random_key(&KmsRng::new(), cipher).unwrap();
    let iv = random_nonce(&KmsRng::new(), cipher).unwrap();

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
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Chacha20Poly1305).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Chacha20Poly1305).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
fn test_encrypt_decrypt_aes_gcm_siv_128() {
    // Load default provider module from OpenSSL.
    let _provider = Provider::load(None, "default").unwrap();

    let mut message = vec![0_u8; 42];
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes128GcmSiv).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Aes128GcmSiv).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
    // Load default provider module from OpenSSL.
    let _provider = Provider::load(None, "default").unwrap();

    let mut message = vec![0_u8; 42];
    KmsRng::new().fill_bytes(&mut message).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes256GcmSiv).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Aes256GcmSiv).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
    KmsRng::new().fill_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 29];
    KmsRng::new().fill_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    KmsRng::new().fill_bytes(&mut message3).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes256Gcm).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Aes256Gcm).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
    KmsRng::new().fill_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 29];
    KmsRng::new().fill_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    KmsRng::new().fill_bytes(&mut message3).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Chacha20Poly1305).unwrap();

    let nonce = random_nonce(&KmsRng::new(), SymCipher::Chacha20Poly1305).unwrap();

    let mut aad = vec![0_u8; 24];
    KmsRng::new().fill_bytes(&mut aad).unwrap();

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
    KmsRng::new().fill_bytes(&mut message1).unwrap();
    let mut message2 = vec![0_u8; 27];
    KmsRng::new().fill_bytes(&mut message2).unwrap();
    let mut message3 = vec![0_u8; 17];
    KmsRng::new().fill_bytes(&mut message3).unwrap();

    let key = random_key(&KmsRng::new(), SymCipher::Aes256Xts).unwrap();

    let tweak = random_nonce(&KmsRng::new(), SymCipher::Aes256Xts).unwrap();

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
    assert_eq!(tag.len(), 0); // XTS has no tag
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

#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
mod mutation_regressions {
    use cosmian_kmip::{
        kmip_0::kmip_types::BlockCipherMode, kmip_2_1::kmip_types::CryptographicAlgorithm,
    };

    use super::*;
    use crate::CryptoError;

    #[cfg(not(feature = "non-fips"))]
    fn provider() -> Result<Provider, CryptoError> {
        Ok(Provider::load(None, "fips")?)
    }

    #[cfg(feature = "non-fips")]
    fn provider() -> Result<Provider, CryptoError> {
        Ok(Provider::load(None, "default")?)
    }

    #[test]
    fn aes_mode_and_key_size_selection() -> Result<(), CryptoError> {
        let cases: [(BlockCipherMode, &[SymCipher]); 6] = [
            (
                BlockCipherMode::ECB,
                &[
                    SymCipher::Aes128Ecb,
                    SymCipher::Aes192Ecb,
                    SymCipher::Aes256Ecb,
                ],
            ),
            (
                BlockCipherMode::CBC,
                &[
                    SymCipher::Aes128Cbc,
                    SymCipher::Aes192Cbc,
                    SymCipher::Aes256Cbc,
                ],
            ),
            (
                BlockCipherMode::GCM,
                &[
                    SymCipher::Aes128Gcm,
                    SymCipher::Aes192Gcm,
                    SymCipher::Aes256Gcm,
                ],
            ),
            (
                BlockCipherMode::XTS,
                &[SymCipher::Aes128Xts, SymCipher::Aes256Xts],
            ),
            (
                BlockCipherMode::AESKeyWrapPadding,
                &[
                    SymCipher::Rfc5649_16,
                    SymCipher::Rfc5649_24,
                    SymCipher::Rfc5649_32,
                ],
            ),
            (
                BlockCipherMode::NISTKeyWrap,
                &[
                    SymCipher::Rfc3394_16,
                    SymCipher::Rfc3394_24,
                    SymCipher::Rfc3394_32,
                ],
            ),
        ];
        for (mode, ciphers) in cases {
            for &expected in ciphers {
                let actual = SymCipher::from_algorithm_and_key_size(
                    CryptographicAlgorithm::AES,
                    Some(mode),
                    expected.key_size(),
                )?;
                assert_eq!(
                    std::mem::discriminant(&actual),
                    std::mem::discriminant(&expected)
                );
                assert_eq!(
                    actual.allows_variable_nonce(),
                    matches!(mode, BlockCipherMode::GCM)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn ecb_padding_and_block_alignment() -> Result<(), CryptoError> {
        let _provider = provider()?;
        for cipher in [
            SymCipher::Aes128Ecb,
            SymCipher::Aes192Ecb,
            SymCipher::Aes256Ecb,
        ] {
            let key = random_key(&KmsRng::new(), cipher)?;
            let cases: [(Option<PaddingMethod>, &[u8]); 3] = [
                (None, &[0x41; 32]),
                (Some(PaddingMethod::None), &[0x41; 32]),
                (Some(PaddingMethod::PKCS5), &[0x41; 17]),
            ];
            for (padding, plaintext) in cases {
                let (ciphertext, tag) = encrypt(cipher, &key, &[], &[], plaintext, padding)?;
                assert_eq!(ciphertext.len(), 32);
                assert_eq!(tag, Vec::<u8>::new());
                assert_eq!(
                    decrypt(cipher, &key, &[], &[], &ciphertext, &tag, padding)?.as_slice(),
                    plaintext
                );
            }
            assert!(matches!(
                encrypt(cipher, &key, &[], &[], &[0x41; 17], Some(PaddingMethod::None)),
                Err(CryptoError::InvalidSize(message))
                    if message == "Plaintext must be a multiple of the block size when no padding is used"
            ));
            assert!(matches!(
                decrypt(cipher, &key, &[], &[], &[0x41; 17], &[], Some(PaddingMethod::None)),
                Err(CryptoError::InvalidSize(message))
                    if message == "Ciphertext must be a multiple of the block size when no padding is used"
            ));
        }
        Ok(())
    }

    #[test]
    fn xts_accepts_one_block_and_rejects_short_plaintext() -> Result<(), CryptoError> {
        let _provider = provider()?;
        for cipher in [SymCipher::Aes128Xts, SymCipher::Aes256Xts] {
            let key = random_key(&KmsRng::new(), cipher)?;
            let nonce = random_nonce(&KmsRng::new(), cipher)?;
            let plaintext = [0x41; 16];
            let (ciphertext, tag) = encrypt(cipher, &key, &nonce, &[], &plaintext, None)?;
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_eq!(tag, Vec::<u8>::new());
            assert_eq!(
                decrypt(cipher, &key, &nonce, &[], &ciphertext, &tag, None)?.as_slice(),
                plaintext
            );
            assert!(matches!(
                encrypt(cipher, &key, &nonce, &[], &[0x41; 15], None),
                Err(CryptoError::InvalidSize(message))
                    if message == "Plaintext is too short for XTS block encryption"
            ));
        }
        Ok(())
    }

    #[test]
    fn cbc_streaming_has_no_authentication_tag() -> Result<(), CryptoError> {
        let _provider = provider()?;
        let cipher = SymCipher::Aes256Cbc;
        let key = random_key(&KmsRng::new(), cipher)?;
        let nonce = random_nonce(&KmsRng::new(), cipher)?;
        let plaintext = [0x41; 33];
        let mut encryption = cipher.stream_cipher(Mode::Encrypt, &key, &nonce, &[])?;
        let mut ciphertext = encryption.update(&plaintext)?;
        let (remainder, tag) = encryption.finalize_encryption()?;
        ciphertext.extend(remainder);
        assert_eq!(tag, Vec::<u8>::new());
        assert_eq!(ciphertext.len(), 48);
        let mut decryption = cipher.stream_cipher(Mode::Decrypt, &key, &nonce, &[])?;
        let mut decrypted = decryption.update(&ciphertext)?;
        decrypted.extend(decryption.finalize_decryption(&tag)?);
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn streaming_update_parks_only_the_tail() -> Result<(), CryptoError> {
        let _provider = provider()?;
        let cipher = SymCipher::Aes128Xts;
        let key = random_key(&KmsRng::new(), cipher)?;
        let nonce = random_nonce(&KmsRng::new(), cipher)?;
        let mut encryption = cipher.stream_cipher(Mode::Encrypt, &key, &nonce, &[])?;
        // 4 blocks in: one block stays parked, 3 are encrypted and returned immediately
        assert_eq!(encryption.update(&[0x41; 64])?.len(), 48);
        // 20 bytes in: 16 (parked) + 20 = 36, tail = 36 % 16 + 16 = 20, so 16 bytes come out
        assert_eq!(encryption.update(&[0x42; 20])?.len(), 16);
        Ok(())
    }

    #[test]
    fn key_wrap_rejects_invalid_lengths_before_openssl() -> Result<(), CryptoError> {
        use crate::crypto::symmetric::{
            rfc3394::{rfc3394_unwrap, rfc3394_wrap},
            rfc5649::rfc5649_unwrap,
        };

        let _provider = provider()?;
        let key = random_key(&KmsRng::new(), SymCipher::Rfc3394_16)?;
        for size in [0, 8, 15, 17, 23] {
            assert!(matches!(
                rfc3394_wrap(&vec![0x41; size], &key),
                Err(CryptoError::InvalidSize(message))
                    if message == "The plaintext size should be >= 16 and a multiple of 8"
            ));
        }
        for size in [0, 8, 16, 23, 25] {
            assert!(matches!(
                rfc3394_unwrap(&vec![0x41; size], &key),
                Err(CryptoError::InvalidSize(message))
                    if message == "The ciphertext size should be >= 24 and a multiple of 8"
            ));
        }
        for size in [0, 8, 15, 17] {
            assert!(matches!(
                rfc5649_unwrap(&vec![0x41; size], &key),
                Err(CryptoError::InvalidSize(message))
                    if message == "The ciphertext size should be >= 16 and a multiple of 8"
            ));
        }
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn non_fips_mode_and_key_size_selection() -> Result<(), CryptoError> {
        for (algorithm, mode, expected) in [
            (
                CryptographicAlgorithm::AES,
                Some(BlockCipherMode::GCMSIV),
                SymCipher::Aes128GcmSiv,
            ),
            (
                CryptographicAlgorithm::AES,
                Some(BlockCipherMode::GCMSIV),
                SymCipher::Aes256GcmSiv,
            ),
            (CryptographicAlgorithm::ChaCha20, None, SymCipher::Chacha20),
            (
                CryptographicAlgorithm::ChaCha20Poly1305,
                None,
                SymCipher::Chacha20Poly1305,
            ),
        ] {
            let actual =
                SymCipher::from_algorithm_and_key_size(algorithm, mode, expected.key_size())?;
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
            assert!(!actual.allows_variable_nonce());
        }
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn chacha20_roundtrip_and_input_sizes() -> Result<(), CryptoError> {
        let _provider = provider()?;
        let cipher = SymCipher::Chacha20;
        let key = random_key(&KmsRng::new(), cipher)?;
        let nonce = random_nonce(&KmsRng::new(), cipher)?;
        let plaintext = [0x41; 65];
        let (ciphertext, tag) = encrypt(cipher, &key, &nonce, &[], &plaintext, None)?;
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);
        assert_eq!(tag, Vec::<u8>::new());
        assert_eq!(
            decrypt(cipher, &key, &nonce, &[], &ciphertext, &tag, None)?.as_slice(),
            plaintext
        );
        for (bad_key, bad_nonce, expected) in [
            (
                [0; 31].as_slice(),
                nonce.as_slice(),
                "ChaCha20 key must be 32 bytes. Got 31",
            ),
            (
                key.as_slice(),
                [0; 7].as_slice(),
                "ChaCha20 nonce must be 8 bytes. Got 7",
            ),
        ] {
            assert!(matches!(
                encrypt(cipher, bad_key, bad_nonce, &[], &plaintext, None),
                Err(CryptoError::InvalidSize(message)) if message == expected
            ));
            assert!(matches!(
                decrypt(cipher, bad_key, bad_nonce, &[], &ciphertext, &tag, None),
                Err(CryptoError::InvalidSize(message)) if message == expected
            ));
        }
        Ok(())
    }
}

mod properties {
    use proptest::{collection::vec, prelude::*};

    use super::{SymCipher, decrypt, encrypt};
    use crate::crypto::symmetric::{
        rfc3394::{rfc3394_unwrap, rfc3394_wrap},
        rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    };

    #[cfg(not(feature = "non-fips"))]
    fn load_fips_provider() {
        openssl::provider::Provider::load(None, "fips").unwrap();
    }

    #[cfg(feature = "non-fips")]
    const fn load_fips_provider() {}

    fn kek() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![Just(16_usize), Just(24), Just(32)].prop_flat_map(|n| vec(any::<u8>(), n))
    }

    fn gcm() -> impl Strategy<Value = (SymCipher, Vec<u8>, Vec<u8>)> {
        prop_oneof![Just(SymCipher::Aes128Gcm), Just(SymCipher::Aes256Gcm)].prop_flat_map(|c| {
            (
                Just(c),
                vec(any::<u8>(), c.key_size()),
                vec(any::<u8>(), c.nonce_size()),
            )
        })
    }

    proptest! {
        #[test]
        fn rfc5649_roundtrip(kek in kek(), pt in vec(any::<u8>(), 1..=512)) {
            load_fips_provider();
            let wrapped = rfc5649_wrap(&pt, &kek).unwrap();
            prop_assert_eq!(rfc5649_unwrap(&wrapped, &kek).unwrap().to_vec(), pt);
        }

        #[test]
        fn rfc5649_rejects_tampering(
            kek in kek(), pt in vec(any::<u8>(), 1..=512),
            idx in any::<prop::sample::Index>(), mask in 1_u8..,
        ) {
            load_fips_provider();
            let mut wrapped = rfc5649_wrap(&pt, &kek).unwrap();
            let i = idx.index(wrapped.len());
            if let Some(b) = wrapped.get_mut(i) {
                *b ^= mask;
            }
            prop_assert!(rfc5649_unwrap(&wrapped, &kek).is_err());
        }

        #[test]
        fn rfc3394_roundtrip(kek in kek(), blocks in vec(any::<[u8; 8]>(), 2..=64)) {
            load_fips_provider();
            let pt = blocks.concat();
            let wrapped = rfc3394_wrap(&pt, &kek).unwrap();
            prop_assert_eq!(rfc3394_unwrap(&wrapped, &kek).unwrap().to_vec(), pt);
        }

        #[test]
        fn rfc3394_rejects_tampering(
            kek in kek(), blocks in vec(any::<[u8; 8]>(), 2..=64),
            idx in any::<prop::sample::Index>(), mask in 1_u8..,
        ) {
            load_fips_provider();
            let mut wrapped = rfc3394_wrap(&blocks.concat(), &kek).unwrap();
            let i = idx.index(wrapped.len());
            if let Some(b) = wrapped.get_mut(i) {
                *b ^= mask;
            }
            prop_assert!(rfc3394_unwrap(&wrapped, &kek).is_err());
        }

        #[test]
        fn aes_gcm_roundtrip(
            (cipher, key, nonce) in gcm(),
            aad in vec(any::<u8>(), 0..=64), pt in vec(any::<u8>(), 0..=1024),
        ) {
            load_fips_provider();
            let (ct, tag) = encrypt(cipher, &key, &nonce, &aad, &pt, None).unwrap();
            prop_assert_eq!(ct.len(), pt.len());
            let dec = decrypt(cipher, &key, &nonce, &aad, &ct, &tag, None).unwrap();
            prop_assert_eq!(dec.to_vec(), pt);
        }

        #[test]
        fn aes_gcm_rejects_tampering(
            (cipher, key, nonce) in gcm(),
            aad in vec(any::<u8>(), 0..=64), pt in vec(any::<u8>(), 0..=1024),
            idx in any::<prop::sample::Index>(), mask in 1_u8..,
        ) {
            load_fips_provider();
            let (ct, tag) = encrypt(cipher, &key, &nonce, &aad, &pt, None).unwrap();
            let mut sealed = [ct.as_slice(), tag.as_slice()].concat();
            let i = idx.index(sealed.len());
            if let Some(b) = sealed.get_mut(i) {
                *b ^= mask;
            }
            let (ct2, tag2) = sealed.split_at(ct.len());
            prop_assert!(decrypt(cipher, &key, &nonce, &aad, ct2, tag2, None).is_err());
        }
    }
}

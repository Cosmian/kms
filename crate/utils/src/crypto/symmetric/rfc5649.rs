//! Symmetrically wrap keys using RFC 5649 available at:
//! -> https://datatracker.ietf.org/doc/html/rfc5649
//!
//! This RFC is an improvement of RFC 3394 and allows to wrap keys of any size.
//! This is done by introducing an Integrity Check Register (ICR) of 64 bits. The
//! encryption algorithm is fed blocks of 64 bits concatenated to the ICR for a
//! total of 128 bits blocks. AES in ECB mode is used since padding and integrity
//! check are done manually following the RFC.
//!
//! OpenSSL unfortunately does not provide a way to use AES-KWP directly.
//! See: https://github.com/openssl/openssl/issues/10605
//! Google provides a patch : https://cloud.google.com/kms/docs/configuring-openssl-for-manual-key-wrapping
//! and so does AWS: https://repost.aws/en/knowledge-center/patch-openssl-cloudhsm

use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use zeroize::Zeroizing;

use crate::error::KmipUtilsError;

pub const AES_KWP_KEY_SIZE: usize = 0x20;
const DEFAULT_RFC5649_CONST: u32 = 0xA659_59A6_u32;
const DEFAULT_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
const AES_WRAP_PAD_BLOCK_SIZE: usize = 0x8;
const AES_BLOCK_SIZE: usize = 0x10;

/// Build the iv according to the RFC 5649.
///
/// `wrapped_key_size` is the size of the key to wrap.
fn build_iv(wrapped_key_size: usize) -> u64 {
    u64::from(DEFAULT_RFC5649_CONST) << 32 | u64::from((wrapped_key_size as u32).to_le())
}

/// Check if the `iv` value obtained after decryption is appropriate according
/// to the RFC 5649.
fn check_iv(iv: u64, data: &[u8]) -> bool {
    let data_size: usize = data.len();
    if (iv >> 32) as u32 != DEFAULT_RFC5649_CONST {
        return false
    }

    let real_data_size = u32::to_le(iv as u32) as usize;
    if real_data_size > data_size || real_data_size <= (data_size - 8) {
        return false
    }

    data[real_data_size..].iter().all(|&x| x == 0)
}

/// Wrap a plain text of variable length following RFC 5649.
///
/// KEK stands for `Key-Encryption Key`
/// The function name matches the one used in the RFC and has no link to the
/// unwrap function in Rust.
pub fn rfc5649_wrap(plain: &[u8], kek: &[u8]) -> Result<Vec<u8>, KmipUtilsError> {
    let n = plain.len();
    let n_bytes_key = n % 8;

    // Pad the plaintext with null bytes.
    let padded_plain = if n_bytes_key != 0 {
        let missing_bytes = 8 - n_bytes_key;
        [plain.to_vec(), vec![0u8; missing_bytes]].concat()
    } else {
        plain.to_vec()
    };

    if n <= 8 {
        // (C[0] | C[1]) = ENC(K, A | P[1]).
        let iv_and_key = [
            &build_iv(n).to_be_bytes(),
            &padded_plain[0..AES_WRAP_PAD_BLOCK_SIZE],
        ]
        .concat();

        /*
         * Encrypt block using AES with ECB mode i.e. raw AES as specified in
         * RFC5649.
         */
        let ciphertext = match kek.len() {
            16 => encrypt(Cipher::aes_128_ecb(), kek, None, &iv_and_key)?,
            24 => encrypt(Cipher::aes_192_ecb(), kek, None, &iv_and_key)?,
            32 => encrypt(Cipher::aes_256_ecb(), kek, None, &iv_and_key)?,
            _ => {
                return Err(KmipUtilsError::InvalidSize(
                    "The kek size should be 16, 24 or 32".to_string(),
                ))
            }
        };

        Ok(ciphertext[..AES_BLOCK_SIZE].to_vec())
    } else {
        _wrap_64(&padded_plain, kek, Some(build_iv(n)))
    }
}

/// Unwrap to a plain text of variable length according to RFC 5649.
///
/// The function name matches the one used in the RFC and has no link to the
/// unwrap function in Rust.
pub fn rfc5649_unwrap(ciphertext: &[u8], kek: &[u8]) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let n = ciphertext.len();

    if n % AES_WRAP_PAD_BLOCK_SIZE != 0 || n < AES_BLOCK_SIZE {
        return Err(KmipUtilsError::InvalidSize(
            "The ciphertext size should be >= 16 and a multiple of 16.".to_string(),
        ))
    }

    if n > 16 {
        let (iv, padded_plain) = _unwrap_64(ciphertext, kek)?;

        // Verify integrity check register as described in RFC 5649.
        if !check_iv(iv, &padded_plain) {
            return Err(KmipUtilsError::InvalidSize(
                "The ciphertext is invalid. Decrypted IV is not appropriate".to_string(),
            ))
        }

        let unpadded_size = u32::from_le(iv as u32) as usize;
        Ok(Zeroizing::from(padded_plain[0..unpadded_size].to_vec()))
    } else {
        /*
         * Encrypt block using AES with ECB mode i.e. raw AES as specified in
         * RFC5649.
         * Make use of OpenSSL Crypter interface to decrypt blocks incrementally
         * without padding since RFC5649 has special padding methods.
         */
        let mut decrypt_cipher = match kek.len() {
            16 => Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, kek, None)?,
            24 => Crypter::new(Cipher::aes_192_ecb(), Mode::Decrypt, kek, None)?,
            32 => Crypter::new(Cipher::aes_256_ecb(), Mode::Decrypt, kek, None)?,
            _ => {
                return Err(KmipUtilsError::InvalidSize(
                    "The kek size should be 16, 24 or 32 bytes".to_string(),
                ))
            }
        };
        decrypt_cipher.pad(false);

        //// A | P[1] = DEC(K, C[0] | C[1])
        let mut plaintext = Zeroizing::from(vec![0; ciphertext.len() + AES_BLOCK_SIZE]);
        let mut dec_len = decrypt_cipher.update(ciphertext, &mut plaintext)?;
        dec_len += decrypt_cipher.finalize(&mut plaintext)?;
        plaintext.truncate(dec_len);

        // Verify integrity check register as described in RFC 5649.
        if !check_iv(
            u64::from_be_bytes(plaintext[0..AES_WRAP_PAD_BLOCK_SIZE].try_into()?),
            &plaintext[AES_WRAP_PAD_BLOCK_SIZE..16],
        ) {
            return Err(KmipUtilsError::InvalidSize(
                "The ciphertext is invalid. Decrypted IV is not appropriate".to_string(),
            ))
        }

        let unpadded_size = u32::from_be_bytes(plaintext[4..8].try_into()?) as usize;

        Ok(Zeroizing::from(
            plaintext[AES_WRAP_PAD_BLOCK_SIZE..(AES_WRAP_PAD_BLOCK_SIZE + unpadded_size)].to_vec(),
        ))
    }
}

/// Wrap a plain text of a 64-bits modulo size according to RFC 3394.
///
/// The function name matches the one used in the RFC and has no link to the
/// unwrap function in Rust.
fn _wrap_64(plain: &[u8], kek: &[u8], iv: Option<u64>) -> Result<Vec<u8>, KmipUtilsError> {
    let n = plain.len();

    if n % AES_WRAP_PAD_BLOCK_SIZE != 0 {
        return Err(KmipUtilsError::InvalidSize(
            "The plaintext size should be a multiple of 8".to_string(),
        ))
    }

    // Number of 64-bit blocks (block size for RFC 5649).
    let n = n / AES_WRAP_PAD_BLOCK_SIZE;

    // ICR stands for Integrity Check Register initially containing the IV.
    let mut icr = iv.unwrap_or(DEFAULT_IV);
    let mut blocks = Vec::with_capacity(n);

    for chunk in plain.chunks(AES_WRAP_PAD_BLOCK_SIZE) {
        blocks.push(u64::from_be_bytes(chunk.try_into()?));
    }
    let cipher = match kek.len() {
        16 => Cipher::aes_128_ecb(),
        24 => Cipher::aes_192_ecb(),
        32 => Cipher::aes_256_ecb(),
        _ => {
            return Err(KmipUtilsError::InvalidSize(
                "The kek size should be 16, 24 or 32".to_string(),
            ))
        }
    };

    for j in 0..6 {
        for (i, block) in blocks.iter_mut().enumerate().take(n) {
            // B = AES(K, A | R[i])
            let plaintext_block = (u128::from(icr) << 64 | u128::from(*block)).to_be_bytes();

            /*
             * Encrypt block using AES with ECB mode i.e. raw AES as specified in
             * RFC5649.
             */
            let ciphertext = encrypt(cipher, kek, None, &plaintext_block)?;

            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = ((n * j) + (i + 1)) as u64;

            icr = u64::from_be_bytes(ciphertext[0..8].try_into()?) ^ t;
            *block = u64::from_be_bytes(ciphertext[8..16].try_into()?);
        }
    }

    let mut wrapped_key = Vec::with_capacity(8 * (blocks.len() + 1));
    wrapped_key.extend(icr.to_be_bytes());
    for block in blocks {
        wrapped_key.extend(block.to_be_bytes());
    }

    Ok(wrapped_key)
}

fn _unwrap_64(ciphertext: &[u8], kek: &[u8]) -> Result<(u64, Zeroizing<Vec<u8>>), KmipUtilsError> {
    let n = ciphertext.len();

    if n % AES_WRAP_PAD_BLOCK_SIZE != 0 || n < AES_BLOCK_SIZE {
        return Err(KmipUtilsError::InvalidSize(
            "The ciphertext size should be >= 16 and a multiple of 8".to_string(),
        ))
    }

    // Number of 64-bit blocks minus 1
    let n = n / 8 - 1;

    let mut blocks = Zeroizing::from(Vec::with_capacity(n + 1));
    for chunk in ciphertext.chunks(AES_WRAP_PAD_BLOCK_SIZE) {
        blocks.push(u64::from_be_bytes(chunk.try_into()?));
    }

    // ICR stands for Integrity Check Register initially containing the IV.
    let mut icr = blocks[0];

    /*
     * Encrypt block using AES with ECB mode i.e. raw AES as specified in
     * RFC5649.
     * Make use of OpenSSL Crypter interface to decrypt blocks incrementally
     * without padding since RFC5649 has special padding methods.
     */
    let mut decrypt_cipher = match kek.len() {
        16 => Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, kek, None)?,
        24 => Crypter::new(Cipher::aes_192_ecb(), Mode::Decrypt, kek, None)?,
        32 => Crypter::new(Cipher::aes_256_ecb(), Mode::Decrypt, kek, None)?,
        _ => {
            return Err(KmipUtilsError::InvalidSize(
                "The kek size should be 16, 24 or 32".to_string(),
            ))
        }
    };
    decrypt_cipher.pad(false);

    for j in (0..6).rev() {
        for (i, block) in blocks[1..].iter_mut().rev().enumerate().take(n) {
            let t = ((n * j) + (n - i)) as u64;

            // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
            let big_i = (u128::from(icr ^ t) << 64 | u128::from(*block)).to_be_bytes();
            let big_b = big_i.as_slice();

            let mut plaintext = Zeroizing::from(vec![0; big_b.len() + AES_BLOCK_SIZE]);
            let mut dec_len = decrypt_cipher.update(big_b, &mut plaintext)?;
            dec_len += decrypt_cipher.finalize(&mut plaintext)?;
            plaintext.truncate(dec_len);

            // A = MSB(64, B)
            icr = u64::from_be_bytes(plaintext[0..AES_WRAP_PAD_BLOCK_SIZE].try_into()?);

            // R[i] = LSB(64, B)
            *block = u64::from_be_bytes(
                plaintext[AES_WRAP_PAD_BLOCK_SIZE..AES_WRAP_PAD_BLOCK_SIZE * 2].try_into()?,
            );
        }
    }

    let mut unwrapped_key = Zeroizing::from(Vec::with_capacity((blocks.len() - 1) * 8));
    for block in &blocks[1..] {
        unwrapped_key.extend(block.to_be_bytes());
    }

    Ok((icr, unwrapped_key))
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;
    use crate::crypto::symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap};

    #[test]
    pub fn test_wrap1() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let key_to_wrap =
             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let wrapped_key = [
            199, 131, 191, 63, 110, 233, 156, 72, 218, 187, 196, 16, 226, 132, 197, 44, 191, 117,
            133, 120, 152, 157, 225, 138, 50, 148, 201, 164, 209, 151, 200, 162, 98, 112, 72, 139,
            28, 233, 128, 22,
        ];

        assert_eq!(
            rfc5649_wrap(key_to_wrap, kek).expect("Fail to wrap"),
            wrapped_key
        );
        assert_eq!(
            rfc5649_unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            Zeroizing::from(key_to_wrap.to_vec())
        );

        const TEST_SIZE_LIMIT: usize = 100;
        for size in 1..=TEST_SIZE_LIMIT {
            let key_to_wrap = &[0u8; TEST_SIZE_LIMIT][..size];
            let ciphertext = rfc5649_wrap(key_to_wrap, kek).expect("Fail to wrap");
            assert_eq!(
                rfc5649_unwrap(&ciphertext, kek).expect("Fail to unwrap"),
                Zeroizing::from(key_to_wrap.to_vec())
            );
        }
    }

    #[test]
    pub fn test_wrap_large_length() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let key_to_wrap =
            b"\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38";
        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];

        assert_eq!(
            rfc5649_wrap(key_to_wrap, kek).expect("Fail to wrap"),
            wrapped_key
        );
        assert_eq!(
            rfc_5649_unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            key_to_wrap
        );
    }

    #[test]
    pub fn test_wrap_small_length() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let key_to_wrap = b"\x46\x6f\x72\x50\x61\x73\x69";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4f,
        ];

        assert_eq!(
            rfc5649_wrap(key_to_wrap, kek).expect("Fail to wrap"),
            wrapped_key
        );
        assert_eq!(
            rfc5649_unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            Zeroizing::from(key_to_wrap.to_vec())
        );
    }

    #[test]
    pub fn test_wrap_bad_key_size() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        // Small input
        let kek = b"\x00";
        let key_to_wrap = b"\x46\x6f\x72\x50\x61\x73\x69";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4f,
        ];

        assert!(rfc5649_wrap(key_to_wrap, kek).is_err());
        assert!(rfc5649_unwrap(&wrapped_key, kek).is_err());

        // Large input
        let kek = b"\x00";
        let key_to_wrap =
            b"\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38";
        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];

        assert!(rfc5649_wrap(key_to_wrap, kek).is_err());
        assert!(rfc5649_unwrap(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap_bad_input_size() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
        ];

        assert!(rfc5649_unwrap(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap_bad_input_content() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4a,
        ];

        assert!(rfc5649_unwrap(&wrapped_key, kek).is_err());

        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6b,
        ];

        assert!(rfc5649_unwrap(&wrapped_key, kek).is_err());
    }
}

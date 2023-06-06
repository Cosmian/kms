use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Aes192, Aes256,
};

use super::error::CryptoError;

const DEFAULT_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
const DEFAULT_RFC5649_CONST: u32 = 0xA659_59A6_u32;

/// Build the iv according to the RFC 5649
///
/// `data_size` is the size of the key to wrap
fn build_iv(data_size: usize) -> u64 {
    let l = u64::from(DEFAULT_RFC5649_CONST);
    let r = u32::to_le(data_size as u32);

    l << 32 | u64::from(r)
}

/// Check if `iv` value is appropriate according to the RFC 5649
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

/// Wrap a plain text of variable length
///
/// Follows RFC 5649
/// The function name matches the one used in the RFC and has no link to the unwrap function in Rust
pub fn wrap(plain: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let n = plain.len();
    let m = n % 8;

    let padded_plain = if m != 0 {
        // Pad the plaintext octet string on the right with zeros
        let missing_bytes = 8 - m;
        [plain.to_vec(), vec![0u8; missing_bytes]].concat()
    } else {
        plain.to_vec()
    };

    if n <= 8 {
        // (C[0] | C[1]) = ENC(K, A | P[1]).
        let mut x = [&build_iv(n).to_be_bytes(), &padded_plain[0..8]].concat();
        let big_c = GenericArray::from_mut_slice(&mut x);

        match kek.len() {
            16 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes128::new(key);
                cipher.encrypt_block(big_c);
            }
            24 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes192::new(key);
                cipher.encrypt_block(big_c);
            }
            32 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes256::new(key);
                cipher.encrypt_block(big_c);
            }
            _ => {
                return Err(CryptoError::InvalidSize(
                    "The kek size should be 16, 24 or 32".to_string(),
                ))
            }
        };

        Ok(big_c[0..16].to_vec())
    } else {
        _wrap_64(&padded_plain, kek, Some(build_iv(n)))
    }
}

/// Unwrap to a plain text of variable length
///
/// Follows RFC 5649
/// The function name matches the one used in the RFC and has no link to the unwrap function in Rust
pub fn unwrap(ciphertext: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let n = ciphertext.len();

    if n % 8 != 0 || n < 16 {
        return Err(CryptoError::InvalidSize(
            "The ciphertext size should be >= 16 and a multiple of 8".to_string(),
        ))
    }

    if n > 16 {
        let (iv, padded_plain) = _unwrap_64(ciphertext, kek)?;

        if !check_iv(iv, &padded_plain) {
            return Err(CryptoError::InvalidSize(
                "The ciphertext is invalid. Decrypted IV is not appropriate".to_string(),
            ))
        }

        let unpadded_size = u32::from_le(iv as u32) as usize;
        Ok(padded_plain[0..unpadded_size].to_vec())
    } else {
        let mut big_c = ciphertext.to_owned();
        let padded_plain = GenericArray::from_mut_slice(&mut big_c);

        // A | P[1] = DEC(K, C[0] | C[1])
        match kek.len() {
            16 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes128::new(key);
                cipher.decrypt_block(padded_plain);
            }
            24 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes192::new(key);
                cipher.decrypt_block(padded_plain);
            }
            32 => {
                let key = GenericArray::from_slice(kek);
                let cipher = Aes256::new(key);
                cipher.decrypt_block(padded_plain);
            }
            _ => {
                return Err(CryptoError::InvalidSize(
                    "The kek size should be 16, 24 or 32".to_string(),
                ))
            }
        };

        if !check_iv(
            u64::from_be_bytes(padded_plain[0..8].try_into()?),
            &padded_plain[8..16],
        ) {
            return Err(CryptoError::InvalidSize(
                "The ciphertext is invalid. Decrypted IV is not appropriate".to_string(),
            ))
        }

        let unpadded_size = u32::from_be_bytes(padded_plain[4..8].try_into()?) as usize;

        Ok(padded_plain[8..(8 + unpadded_size)].to_vec())
    }
}

/// Wrap a plain text of a 64-bits modulo size
///
/// Follows RFC 3394
/// The function name matches the one used in the RFC and has no link to the unwrap function in Rust
pub fn wrap_64(plain: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    _wrap_64(plain, kek, None)
}

/// Wrap a plain text of a 64-bits modulo size
///
/// Follows RFC 3394
/// The function name matches the one used in the RFC and has no link to the unwrap function in Rust
fn _wrap_64(plain: &[u8], kek: &[u8], iv: Option<u64>) -> Result<Vec<u8>, CryptoError> {
    let n = plain.len();

    if n % 8 != 0 {
        return Err(CryptoError::InvalidSize(
            "The plaintext size should be a multiple of 8".to_string(),
        ))
    }

    // Number of 64-bit blocks
    let n = n / 8;

    let mut big_a = iv.unwrap_or(DEFAULT_IV);
    let mut big_r = Vec::with_capacity(n);

    for chunk in plain.chunks(8) {
        big_r.push(u64::from_be_bytes(chunk.try_into()?));
    }

    for j in 0..6 {
        for (i, r) in big_r.iter_mut().enumerate().take(n) {
            // B = AES(K, A | R[i])
            let big_i: u128 = u128::from(big_a) << 64 | u128::from(*r);
            let mut big_b = GenericArray::from(big_i.to_be_bytes());

            match kek.len() {
                16 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes128::new(key);
                    cipher.encrypt_block(&mut big_b);
                }
                24 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes192::new(key);
                    cipher.encrypt_block(&mut big_b);
                }
                32 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes256::new(key);
                    cipher.encrypt_block(&mut big_b);
                }
                _ => {
                    return Err(CryptoError::InvalidSize(
                        "The kek size should be 16, 24 or 32".to_string(),
                    ))
                }
            };

            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = ((n * j) + (i + 1)) as u64;

            big_a = u64::from_be_bytes(big_b[0..8].try_into()?) ^ t;
            *r = u64::from_be_bytes(big_b[8..16].try_into()?);
        }
    }

    let mut big_c = Vec::with_capacity(8 * (big_r.len() + 1));
    big_c.extend(big_a.to_be_bytes());
    for r in big_r {
        big_c.extend(r.to_be_bytes());
    }

    Ok(big_c)
}

/// Unwrap to a plain text of a 64-bits modulo size
///
/// Follows RFC 3394
/// The function name matches the one used in the RFC and has no link to the unwrap function in Rust
pub fn unwrap_64(cipher: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (iv, plain) = _unwrap_64(cipher, kek)?;

    if iv != DEFAULT_IV {
        return Err(CryptoError::InvalidSize(
            "The ciphertext is invalid. Decrypted IV is not appropriate".to_string(),
        ))
    }

    Ok(plain)
}

fn _unwrap_64(ciphertext: &[u8], kek: &[u8]) -> Result<(u64, Vec<u8>), CryptoError> {
    let n = ciphertext.len();

    if n % 8 != 0 || n < 16 {
        return Err(CryptoError::InvalidSize(
            "The ciphertext size should be >= 16 and a multiple of 8".to_string(),
        ))
    }

    // Number of 64-bit blocks minus 1
    let n = n / 8 - 1;

    let mut big_r: Vec<u64> = Vec::with_capacity(n + 1);
    for chunk in ciphertext.chunks(8) {
        big_r.push(u64::from_be_bytes(chunk.try_into()?));
    }

    let mut big_a = big_r[0];

    for j in (0..6).rev() {
        for (i, r) in big_r[1..].iter_mut().rev().enumerate().take(n) {
            let t = ((n * j) + (n - i)) as u64;

            // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
            let big_i: u128 = u128::from(big_a ^ t) << 64 | u128::from(*r);

            let mut big_b = GenericArray::from(big_i.to_be_bytes());

            match kek.len() {
                16 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes128::new(key);
                    cipher.decrypt_block(&mut big_b);
                }
                24 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes192::new(key);
                    cipher.decrypt_block(&mut big_b);
                }
                32 => {
                    let key = GenericArray::from_slice(kek);
                    let cipher = Aes256::new(key);
                    cipher.decrypt_block(&mut big_b);
                }
                _ => {
                    return Err(CryptoError::InvalidSize(
                        "The kek size should be 16, 24 or 32".to_string(),
                    ))
                }
            };

            // A = MSB(64, B)
            big_a = u64::from_be_bytes(big_b[0..8].try_into()?);

            // R[i] = LSB(64, B)
            *r = u64::from_be_bytes(big_b[8..16].try_into()?);
        }
    }

    let mut big_p = Vec::with_capacity(big_r.len() - 1);
    for r in &big_r[1..] {
        big_p.extend(r.to_be_bytes());
    }

    Ok((big_a, big_p))
}

#[cfg(test)]
mod tests {
    use crate::crypto::key_wrapping_rfc_5649::{unwrap, unwrap_64, wrap, wrap_64};

    #[test]
    pub fn test_wrap64() {
        let kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let key_to_wrap = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
        let wrapped_key = [
            0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x5, 0x81,
            0x8a, 0x2a, 0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
        ];

        assert_eq!(
            wrap_64(key_to_wrap, kek).expect("Fail to wrap"),
            wrapped_key
        );

        assert_eq!(
            unwrap_64(&wrapped_key, kek).expect("Fail to unwrap"),
            key_to_wrap
        );
    }

    #[test]
    pub fn test_wrap64_bad_key_size() {
        let kek = b"\x00";
        let key_to_wrap = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
        let wrapped_key = [
            0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x5, 0x81,
            0x8a, 0x2a, 0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
        ];

        assert!(wrap_64(key_to_wrap, kek).is_err());

        assert!(unwrap_64(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap64_bad_input_size() {
        let kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let key_to_wrap = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE";
        let wrapped_key = [
            0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x5, 0x81,
            0x8a, 0x2a, 0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a,
        ];

        assert!(wrap_64(key_to_wrap, kek).is_err());

        assert!(unwrap_64(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap64_bad_input_content() {
        let kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let wrapped_key = [
            0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x5, 0x81,
            0x8a, 0x2a, 0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe8,
        ];

        assert!(unwrap_64(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap_large_length() {
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let key_to_wrap =
            b"\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38";
        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];

        assert_eq!(wrap(key_to_wrap, kek).expect("Fail to wrap"), wrapped_key);
        assert_eq!(
            unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            key_to_wrap
        );
    }

    #[test]
    pub fn test_wrap_small_length() {
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let key_to_wrap = b"\x46\x6f\x72\x50\x61\x73\x69";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4f,
        ];

        assert_eq!(wrap(key_to_wrap, kek).expect("Fail to wrap"), wrapped_key);
        assert_eq!(
            unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            key_to_wrap
        );
    }

    #[test]
    pub fn test_wrap_bad_key_size() {
        // Small input
        let kek = b"\x00";
        let key_to_wrap = b"\x46\x6f\x72\x50\x61\x73\x69";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4f,
        ];

        assert!(wrap(key_to_wrap, kek).is_err());
        assert!(unwrap(&wrapped_key, kek).is_err());

        // Large input
        let kek = b"\x00";
        let key_to_wrap =
            b"\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38";
        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];

        assert!(wrap(key_to_wrap, kek).is_err());
        assert!(unwrap(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap_bad_input_size() {
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
        ];

        assert!(unwrap(&wrapped_key, kek).is_err());
    }

    #[test]
    pub fn test_wrap_bad_input_content() {
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4a,
        ];

        assert!(unwrap(&wrapped_key, kek).is_err());

        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6b,
        ];

        assert!(unwrap(&wrapped_key, kek).is_err());
    }
}

//! AES Key Wrap (RFC 3394) without padding (KW)
//! Implements wrapping/unwrapping using raw AES-ECB via rust-openssl.
//!
//! Spec references:
//! - RFC 3394: <https://datatracker.ietf.org/doc/html/rfc3394>
//! - NIST SP 800-38F: <https://csrc.nist.gov/pubs/sp/800/38/f/final>
//!
//! Notes:
//! - Input must be a multiple of 8 bytes and at least 16 bytes (n >= 2 blocks).
//! - Uses the default IV (A) = 0xA6A6A6A6A6A6A6A6.
//! - No padding is performed; for non-8-byte input lengths, use RFC 5649 (KWP).

use openssl::symm::{Cipher, Crypter, Mode, encrypt};
use zeroize::Zeroizing;

use crate::error::{CryptoError, result::CryptoResult};

const DEFAULT_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
const AES_WRAP_BLOCK_SIZE: usize = 0x8; // 64-bit
const AES_BLOCK_SIZE: usize = 0x10; // 128-bit

fn select_cipher(kek: &[u8]) -> CryptoResult<Cipher> {
    Ok(match kek.len() {
        16 => Cipher::aes_128_ecb(),
        24 => Cipher::aes_192_ecb(),
        32 => Cipher::aes_256_ecb(),
        _ => {
            return Err(CryptoError::InvalidSize(
                "The KEK size should be 16, 24 or 32 bytes".to_owned(),
            ));
        }
    })
}

/// Wrap a plaintext key using AES Key Wrap (RFC 3394).
pub fn rfc3394_wrap(plain: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let n_bytes = plain.len();

    if !n_bytes.is_multiple_of(AES_WRAP_BLOCK_SIZE) || n_bytes < 2 * AES_WRAP_BLOCK_SIZE {
        return Err(CryptoError::InvalidSize(
            "The plaintext size should be >= 16 and a multiple of 8".to_owned(),
        ));
    }

    let n_blocks = n_bytes / AES_WRAP_BLOCK_SIZE;
    let cipher = select_cipher(kek)?;

    // Initialize A (ICR) with default IV and load R[i]
    let mut a: u64 = DEFAULT_IV;
    let mut r: Vec<u64> = Vec::with_capacity(n_blocks);
    for chunk in plain.chunks(AES_WRAP_BLOCK_SIZE) {
        r.push(u64::from_be_bytes(chunk.try_into()?));
    }

    // 6 rounds
    for j in 0..6 {
        for (i, block) in r.iter_mut().enumerate() {
            // B = AES(K, A | R[i])
            let plaintext_block = ((u128::from(a) << 64) | u128::from(*block)).to_be_bytes();
            let b = encrypt(cipher, kek, None, &plaintext_block)?;

            // A = MSB(64, B) ^ t, where t = (n*j)+i+1
            let t = u64::try_from((n_blocks * j) + (i + 1))?;
            a = u64::from_be_bytes(
                b.get(0..AES_WRAP_BLOCK_SIZE)
                    .ok_or_else(|| {
                        CryptoError::InvalidSize(
                            "Encryption output too short for IV extraction".to_owned(),
                        )
                    })?
                    .try_into()?,
            ) ^ t;

            // R[i] = LSB(64, B)
            *block = u64::from_be_bytes(
                b.get(AES_WRAP_BLOCK_SIZE..AES_BLOCK_SIZE)
                    .ok_or_else(|| {
                        CryptoError::InvalidSize(
                            "Encryption output too short for block extraction".to_owned(),
                        )
                    })?
                    .try_into()?,
            );
        }
    }

    // Output C[0] = A, C[1..n] = R[1..n]
    let mut out = Vec::with_capacity(AES_WRAP_BLOCK_SIZE * (n_blocks + 1));
    out.extend_from_slice(&a.to_be_bytes());
    for block in r {
        out.extend_from_slice(&block.to_be_bytes());
    }
    Ok(out)
}

/// Unwrap a ciphertext produced by AES Key Wrap (RFC 3394).
pub fn rfc3394_unwrap(ciphertext: &[u8], kek: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let n_bytes = ciphertext.len();

    // Minimum ciphertext length: 24 bytes (16 for key + 8 for IV) and multiple of 8
    if !n_bytes.is_multiple_of(AES_WRAP_BLOCK_SIZE) || n_bytes < (AES_WRAP_BLOCK_SIZE * 3) {
        return Err(CryptoError::InvalidSize(
            "The ciphertext size should be >= 24 and a multiple of 8".to_owned(),
        ));
    }

    let n_blocks = (n_bytes / AES_WRAP_BLOCK_SIZE) - 1; // exclude C[0]
    let cipher = select_cipher(kek)?;

    // Load C[0] into A, and remainder into R[i]
    let mut blocks = Zeroizing::from(Vec::with_capacity(n_blocks + 1));
    for chunk in ciphertext.chunks(AES_WRAP_BLOCK_SIZE) {
        blocks.push(u64::from_be_bytes(chunk.try_into()?));
    }

    // bonds are guaranteed by earlier validation, and using `get` causes ownership issues
    #[expect(clippy::indexing_slicing)]
    let mut a = blocks[0];

    // Initialize AES-ECB decrypter without padding
    let mut decrypt_cipher = Crypter::new(cipher, Mode::Decrypt, kek, None)?;
    decrypt_cipher.pad(false);

    // 6 rounds in reverse
    for j in (0..6).rev() {
        #[expect(clippy::indexing_slicing)]
        // bonds are garanteed by earlier validation, and using `get` causes ownership issues
        for (i_rev, block) in blocks[1..].iter_mut().rev().enumerate() {
            // t = (n*j) + (n - i), with i in 1..=n; here i_rev enumerates 0..n-1 from end
            let t = u64::try_from((n_blocks * j) + (n_blocks - i_rev))?;

            // B = AES-1(K, (A ^ t) | R[i])
            let big_i = ((u128::from(a ^ t) << 64) | u128::from(*block)).to_be_bytes();
            let mut plaintext = Zeroizing::from(vec![0; AES_BLOCK_SIZE * 2]);
            let mut dec_len = decrypt_cipher.update(&big_i, &mut plaintext)?;
            dec_len += decrypt_cipher.finalize(&mut plaintext)?;
            plaintext.truncate(dec_len);

            // A = MSB(64, B)
            a = u64::from_be_bytes(
                plaintext
                    .get(0..AES_WRAP_BLOCK_SIZE)
                    .ok_or_else(|| {
                        CryptoError::InvalidSize(
                            "Decryption output too short for IV extraction".to_owned(),
                        )
                    })?
                    .try_into()?,
            );

            // R[i] = LSB(64, B)
            *block = u64::from_be_bytes(
                plaintext
                    .get(AES_WRAP_BLOCK_SIZE..AES_WRAP_BLOCK_SIZE * 2)
                    .ok_or_else(|| {
                        CryptoError::InvalidSize(
                            "Decryption output too short for block extraction".to_owned(),
                        )
                    })?
                    .try_into()?,
            );
        }
    }

    // Validate A equals default IV
    if a != DEFAULT_IV {
        return Err(CryptoError::InvalidSize(
            "The ciphertext is invalid. Unwrapped IV does not match RFC 3394".to_owned(),
        ));
    }

    // Collect R[1..n]
    let mut unwrapped = Zeroizing::from(Vec::with_capacity(n_blocks * AES_WRAP_BLOCK_SIZE));
    for block in blocks
        .get(1..)
        .ok_or_else(|| CryptoError::IndexingSlicing("Block index issue".to_owned()))?
    {
        unwrapped.extend_from_slice(&block.to_be_bytes());
    }

    Ok(unwrapped)
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use crate::crypto::symmetric::rfc3394::{rfc3394_unwrap, rfc3394_wrap};

    // Test vectors from RFC 3394 (AES-128 KEK, 128-bit key)
    // KEK = 000102030405060708090A0B0C0D0E0F
    // P   = 00112233445566778899AABBCCDDEEFF
    // C   = 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
    #[test]
    fn test_rfc3394_vector_aes128() {
        #[cfg(not(feature = "non-fips"))]
        openssl::provider::Provider::load(None, "fips").unwrap();

        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let p = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let c_expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

        let c = rfc3394_wrap(&p, &kek).unwrap();
        assert_eq!(c, c_expected);

        let p_unwrapped = rfc3394_unwrap(&c, &kek).unwrap();
        assert_eq!(p_unwrapped, Zeroizing::from(p));
    }

    // Additional sanity: error cases
    #[test]
    fn test_errors() {
        #[cfg(not(feature = "non-fips"))]
        openssl::provider::Provider::load(None, "fips").unwrap();

        // KEK length invalid
        let kek_bad = [0x00_u8; 1];
        let p16 = [0x11_u8; 16];
        rfc3394_wrap(&p16, &kek_bad).unwrap_err();
        let c24 = [0x22_u8; 24];
        rfc3394_unwrap(&c24, &kek_bad).unwrap_err();

        // Plaintext not multiple of 8 or too small
        let kek16 = [0x01_u8; 16];
        let p15 = [0x33_u8; 15];
        rfc3394_wrap(&p15, &kek16).unwrap_err();
        let p8 = [0x44_u8; 8];
        rfc3394_wrap(&p8, &kek16).unwrap_err();

        // Ciphertext too small
        let c16 = [0x55_u8; 16];
        rfc3394_unwrap(&c16, &kek16).unwrap_err();

        // Ciphertext not multiple of 8
        let c23 = [0x66_u8; 23];
        rfc3394_unwrap(&c23, &kek16).unwrap_err();
    }
}

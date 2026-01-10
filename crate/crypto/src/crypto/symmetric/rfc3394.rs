//! AES Key Wrap (RFC 3394) without padding (KW)  via rust-openssl.
//! Please prefer using the RFC 5649, as it's the current standard. This implementation is only made available to comply with API that still support legacy encryption standards.
//!
//! Spec references:
//! - RFC 3394: <https://datatracker.ietf.org/doc/html/rfc3394>
//! - NIST SP 800-38F: <https://csrc.nist.gov/pubs/sp/800/38/f/final>
//!
//! Notes:
//! - Input must be a multiple of 8 bytes and at least 16 bytes (n >= 2 blocks).
//! - No padding is performed; for non-8-byte input lengths, use RFC 5649 (KWP).
use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
};
use zeroize::Zeroizing;

use crate::error::{CryptoError, result::CryptoResult};

const AES_BLOCK_SIZE: usize = 16; // 128-bit
const AES_WRAP_BLOCK_SIZE: usize = 8; // 64-bit

fn select_cipher(kek: &[u8]) -> CryptoResult<&CipherRef> {
    Ok(match kek.len() {
        16 => Cipher::aes_128_wrap(),
        24 => Cipher::aes_192_wrap(),
        32 => Cipher::aes_256_wrap(),
        _ => {
            return Err(CryptoError::InvalidSize(
                "The KEK size should be 16, 24 or 32 bytes".to_owned(),
            ));
        }
    })
}

pub fn rfc3394_wrap(plaintext: &[u8], kek: &[u8]) -> CryptoResult<Vec<u8>> {
    let n_bytes = plaintext.len();

    // RFC 3394 requires plaintext to be at least 16 bytes and a multiple of 8 bytes.
    if !n_bytes.is_multiple_of(AES_WRAP_BLOCK_SIZE) || n_bytes < 2 * AES_WRAP_BLOCK_SIZE {
        return Err(CryptoError::InvalidSize(
            "The plaintext size should be >= 16 and a multiple of 8".to_owned(),
        ));
    }

    let cipher = select_cipher(kek)?;

    // Initialize cipher context for encryption
    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(cipher), Some(kek), None)?;

    // Allocate output buffer: wrapped size is plaintext + 8 bytes (IV) + 2 extra blocks for cipher_final.
    // The extra blocks will not propagate to the result as it's truncated to the actual size. Due to how the openssl library is programmed,
    // not adding at least 1 extra block results in a panic. We chose to add two because that's how the openssl library operates when using this cipher.
    let mut ciphertext = vec![0_u8; n_bytes + AES_WRAP_BLOCK_SIZE + (AES_BLOCK_SIZE * 2)];

    // Perform the key wrap operation
    let mut written = ctx.cipher_update(plaintext, Some(&mut ciphertext))?;
    written += ctx.cipher_final(ciphertext.get_mut(written..).ok_or_else(|| {
        CryptoError::IndexingSlicing("Buffer too small for cipher_final".to_owned())
    })?)?;

    // Truncate to actual output size.
    ciphertext.truncate(written);

    Ok(ciphertext)
}

pub fn rfc3394_unwrap(ciphertext: &[u8], kek: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let n_bytes = ciphertext.len();

    // RFC 3394 requires ciphertext to be at least 24 bytes (16 bytes plaintext + 8 bytes IV) and a multiple of 8.
    if !n_bytes.is_multiple_of(AES_WRAP_BLOCK_SIZE) || n_bytes < 3 * AES_WRAP_BLOCK_SIZE {
        return Err(CryptoError::InvalidSize(
            "The ciphertext size should be >= 24 and a multiple of 8".to_owned(),
        ));
    }

    let cipher = select_cipher(kek)?;

    // Initialize cipher context for decryption.
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(cipher), Some(kek), None)?;

    // Allocate output buffer: unwrapped size is ciphertext - 8 bytes (IV) + extra blocks for cipher_final. Same comments as above.
    let mut plaintext = Zeroizing::new(vec![
        0_u8;
        n_bytes - AES_WRAP_BLOCK_SIZE + (AES_BLOCK_SIZE * 2)
    ]);

    // Perform the key unwrap operation
    let mut written = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
    written += ctx.cipher_final(plaintext.get_mut(written..).ok_or_else(|| {
        CryptoError::IndexingSlicing("Buffer too small for cipher_final".to_owned())
    })?)?;

    // Truncate to actual output size.
    plaintext.truncate(written);

    Ok(plaintext)
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    /// Helper to run wrap/unwrap roundtrip test
    fn test_wrap_unwrap(kek_hex: &str, plaintext_hex: &str, expected_ciphertext_hex: &str) {
        #[cfg(not(feature = "non-fips"))]
        openssl::provider::Provider::load(None, "fips").unwrap();
        let kek = hex::decode(kek_hex).unwrap();
        let p = hex::decode(plaintext_hex).unwrap();
        let c_expected = hex::decode(expected_ciphertext_hex).unwrap();

        let c = rfc3394_wrap(&p, &kek).unwrap();
        assert_eq!(c, c_expected, "Wrap output mismatch");

        let p_unwrapped = rfc3394_unwrap(&c, &kek).unwrap();
        assert_eq!(p_unwrapped, Zeroizing::from(p), "Unwrap output mismatch");
    }

    // RFC 3394 test vectors with AES-128 KEK
    #[test]
    fn test_rfc3394_aes128_kek() {
        // Section 4.1: 128-bit plaintext
        test_wrap_unwrap(
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        );
    }

    // RFC 3394 test vectors with AES-192 KEK
    #[test]
    fn test_rfc3394_aes192_kek() {
        let kek = "000102030405060708090A0B0C0D0E0F1011121314151617";

        // Section 4.2: 128-bit plaintext
        test_wrap_unwrap(
            kek,
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        );

        // Section 4.4: 192-bit plaintext
        test_wrap_unwrap(
            kek,
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        );
    }

    // RFC 3394 test vectors with AES-256 KEK
    #[test]
    fn test_rfc3394_aes256_kek() {
        let kek = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

        // Section 4.3: 128-bit plaintext
        test_wrap_unwrap(
            kek,
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        );

        // Section 4.5: 192-bit plaintext
        test_wrap_unwrap(
            kek,
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        );

        // Section 4.6: 256-bit plaintext
        test_wrap_unwrap(
            kek,
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        );
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

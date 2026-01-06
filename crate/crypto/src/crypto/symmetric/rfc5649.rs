//! AES Key Wrap (RFC 5649) with padding (KWP) via rust-openssl.
//! This is the current standard for AES key wrapping according to the NIST SP 800-38F.
//!
//! Spec references:
//! - RFC 5649: <https://datatracker.ietf.org/doc/html/rfc5649>
//! - NIST SP 800-38F: <https://csrc.nist.gov/pubs/sp/800/38/f/final>
//!
//! This RFC is an improvement of RFC 3394 and allows to wrap keys of any size.
//! This is done by introducing an Integrity Check Register (ICR) of 64 bits. The
//! encryption algorithm is fed blocks of 64 bits concatenated to the ICR for a
//! total of 128 bits blocks.
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use zeroize::Zeroizing;

use crate::error::{CryptoError, result::CryptoResult};

const AES_BLOCK_SIZE: usize = 16; // 128-bit
const AES_WRAP_BLOCK_SIZE: usize = 8; // 64-bit

fn select_cipher_pad(kek: &[u8]) -> CryptoResult<&CipherRef> {
    Ok(match kek.len() {
        16 => Cipher::aes_128_wrap_pad(),
        24 => Cipher::aes_192_wrap_pad(),
        32 => Cipher::aes_256_wrap_pad(),
        _ => {
            return Err(CryptoError::InvalidSize(
                "The KEK size should be 16, 24 or 32 bytes".to_owned(),
            ));
        }
    })
}

pub fn rfc5649_wrap(plaintext: &[u8], kek: &[u8]) -> CryptoResult<Vec<u8>> {
    const MAX_PLAINTEXT_LEN: u64 = 1 << 32;
    let n_bytes = plaintext.len();

    // RFC 5649 requires plaintext to be at least 1 byte and less than 2^32 bytes
    if n_bytes == 0 {
        return Err(CryptoError::InvalidSize(
            "The plaintext size should be at least 1 byte".to_owned(),
        ));
    }

    // Check maximum length (2^32 - 1 bytes as per NIST SP 800-38F Section 5.3.1)
    if u64::try_from(n_bytes).is_ok_and(|n_bytes| n_bytes >= MAX_PLAINTEXT_LEN) {
        return Err(CryptoError::InvalidSize(
            "The plaintext size should be less than 2^32 bytes".to_owned(),
        ));
    }

    let cipher = select_cipher_pad(kek)?;

    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(cipher), Some(kek), None)?;

    // Calculate output size: for KWP, output is always a multiple of 8 bytes
    // Minimum output is 16 bytes (2 "semi-blocks")
    // The wrapped size includes the AIV (8 bytes) plus padded plaintext
    let padded_len = if n_bytes <= AES_WRAP_BLOCK_SIZE {
        AES_WRAP_BLOCK_SIZE // Special case: single block encryption
    } else {
        // Calculate padding: round up to next multiple of 8, then add 8 for AIV
        let padded_plaintext_len = n_bytes.div_ceil(8) * 8;
        padded_plaintext_len + 8
    };

    // Allocate output buffer with extra space for cipher_final
    let mut ciphertext = vec![0_u8; padded_len + AES_BLOCK_SIZE];

    // Perform the key wrap operation
    let mut written = ctx.cipher_update(plaintext, Some(&mut ciphertext))?;
    written += ctx.cipher_final(ciphertext.get_mut(written..).ok_or_else(|| {
        CryptoError::IndexingSlicing("Buffer too small for cipher_final".to_owned())
    })?)?;

    // Truncate to actual output size
    ciphertext.truncate(written);

    Ok(ciphertext)
}

pub fn rfc5649_unwrap(ciphertext: &[u8], kek: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let cipher = select_cipher_pad(kek)?;
    let n_bytes = ciphertext.len();

    // RFC 5649 requires ciphertext to be at least 2 semi-blocks (so 1 block) and a multiple of 8 bytes (complete blocks)
    if !n_bytes.is_multiple_of(AES_WRAP_BLOCK_SIZE) || n_bytes < 2 * AES_WRAP_BLOCK_SIZE {
        return Err(CryptoError::InvalidSize(
            "The ciphertext size should be >= 16 and a multiple of 8".to_owned(),
        ));
    }

    // Initialize cipher context for decryption
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(cipher), Some(kek), None)?;

    // Allocate output buffer: maximum plaintext size is ciphertext - 8 bytes (AIV)
    // Add extra space for cipher_final
    let mut plaintext = Zeroizing::new(vec![0_u8; n_bytes - AES_WRAP_BLOCK_SIZE + AES_BLOCK_SIZE]);

    // Perform the key unwrap operation
    let mut written = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
    written += ctx.cipher_final(plaintext.get_mut(written..).ok_or_else(|| {
        CryptoError::IndexingSlicing("Buffer too small for cipher_final".to_owned())
    })?)?;

    // Truncate to actual output size (OpenSSL's wrap_pad removes padding automatically)
    plaintext.truncate(written);

    Ok(plaintext)
}

#[expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use aes_kw::KeyInit;
    use zeroize::Zeroizing;

    use crate::crypto::symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap};

    // Helper to load FIPS provider before each test (if needed)
    fn setup_openssl_fips_provider() {
        #[cfg(not(feature = "non-fips"))]
        {
            openssl::provider::Provider::load(None, "fips").unwrap();
        }
    }

    #[test]
    pub(super) fn test_wrap_unwrap_minimal() {
        const TEST_SIZE_LIMIT: usize = 100;
        setup_openssl_fips_provider();
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";

        // Empty plaintext should fail
        let empty: &[u8] = &[];
        rfc5649_wrap(empty, kek).unwrap_err();

        // The rest of the round-trips should succeed, including the single byte one
        for size in 1..=TEST_SIZE_LIMIT {
            let key_to_wrap = &[0_u8; TEST_SIZE_LIMIT][..size];
            let ciphertext = rfc5649_wrap(key_to_wrap, kek).expect("Fail to wrap");
            assert_eq!(
                rfc5649_unwrap(&ciphertext, kek).expect("Fail to unwrap"),
                Zeroizing::from(key_to_wrap.to_vec())
            );
        }
    }

    // This test uses the vectors provided by the official RFC paper
    #[test]
    pub(super) fn test_rfc_test_vectors() {
        setup_openssl_fips_provider();
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";

        // 7 bytes of data
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

        // 20 bytes of data
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
            rfc5649_unwrap(&wrapped_key, kek).expect("Fail to unwrap"),
            Zeroizing::from(key_to_wrap.to_vec())
        );
    }

    #[test]
    pub(super) fn test_wrap_bad_key_size() {
        setup_openssl_fips_provider();
        // Small input
        let kek = b"\x00";
        let key_to_wrap = b"\x46\x6f\x72\x50\x61\x73\x69";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4f,
        ];

        rfc5649_wrap(key_to_wrap, kek).unwrap_err();
        rfc5649_unwrap(&wrapped_key, kek).unwrap_err();

        // Large input
        let kek = b"\x00";
        let key_to_wrap =
            b"\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38";
        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];

        rfc5649_wrap(key_to_wrap, kek).unwrap_err();
        rfc5649_unwrap(&wrapped_key, kek).unwrap_err();
    }

    #[test]
    pub(super) fn test_wrap_bad_input_size() {
        setup_openssl_fips_provider();
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
        ];

        rfc5649_unwrap(&wrapped_key, kek).unwrap_err();
    }

    #[test]
    pub(super) fn test_wrap_bad_input_content() {
        setup_openssl_fips_provider();
        let kek = b"\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8";
        let wrapped_key = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x0, 0xf2, 0xcc, 0xb5, 0xb, 0xb2,
            0x4a,
        ];

        rfc5649_unwrap(&wrapped_key, kek).unwrap_err();

        let wrapped_key = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6b,
        ];

        rfc5649_unwrap(&wrapped_key, kek).unwrap_err();
    }

    #[test]
    fn test_sizes() {
        setup_openssl_fips_provider();
        let dek_16 = [1_u8; 16];
        let kek_16 = [2_u8; 16];
        let dek_32 = [1_u8; 32];
        let kek_32 = [2_u8; 32];
        assert_eq!(
            rfc5649_wrap(&dek_16, &kek_16).unwrap().len(),
            dek_16.len() + 8
        );
        assert_eq!(
            rfc5649_wrap(&dek_16, &kek_32).unwrap().len(),
            dek_16.len() + 8
        );
        assert_eq!(
            rfc5649_wrap(&dek_32, &kek_16).unwrap().len(),
            dek_32.len() + 8
        );
        assert_eq!(
            rfc5649_wrap(&dek_32, &kek_32).unwrap().len(),
            dek_32.len() + 8
        );
    }

    #[test]
    fn test_openssl_compat() {
        setup_openssl_fips_provider();
        let kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a85840df6e29b02af1";
        let dek = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";

        // Generating the opensl wrapped key with AES_KEY_WRAP_PAD (RFC 5649)

        // write kek to file
        // std::fs::write("/tmp/kek.bin", hex::decode(kek).unwrap()).unwrap();
        // write dek to file
        // std::fs::write("/tmp/dek.bin", hex::decode(dek).unwrap()).unwrap();

        //  openssl enc \
        //   -id-aes256-wrap-pad \
        //   -iv A65959A6 \
        //   -K $( hexdump -v -e '/1 "%02x"' < /tmp/kek.bin )\
        //   -in /tmp/dek.bin > /tmp/wrapped_key.bin
        //
        //  hexdump -v -e '/1 "%02x"' < /tmp/wrapped_key.bin

        let openssl_wrapped_key =
            "340068e5236ceb5aaca068695fe28266a2dd7b75bdfc46a53f3e4f8c8052f41bd905f3571d04e0f7";

        let rfc5649_wrapped_key = hex::encode(
            rfc5649_wrap(
                hex::decode(dek).unwrap().as_slice(),
                hex::decode(kek).unwrap().as_slice(),
            )
            .unwrap(),
        );
        assert_eq!(openssl_wrapped_key, rfc5649_wrapped_key);
    }

    #[test]
    fn test_aes_kw_compat() {
        setup_openssl_fips_provider();
        // Test the compatibility with AES_KEY_WRAP_PAD (RFC 5649) implemented by the aes_kw crate.
        let kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a85840df6e29b02af1";
        let dek = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";

        let aes_kw_kek = aes_kw::KwpAes256::new_from_slice(&hex::decode(kek).unwrap()).unwrap();
        let input_key = hex::decode(dek).unwrap();
        let mut buf = [0_u8; 128];
        let aes_kw_wrapped_key = hex::encode(aes_kw_kek.wrap_key(&input_key, &mut buf).unwrap());

        let rfc5649_wrapped_key = hex::encode(
            rfc5649_wrap(
                hex::decode(dek).unwrap().as_slice(),
                hex::decode(kek).unwrap().as_slice(),
            )
            .unwrap(),
        );
        assert_eq!(aes_kw_wrapped_key, rfc5649_wrapped_key);
    }
}

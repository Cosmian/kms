//! In-memory AES-GCM encrypt/decrypt for JWE content encryption.
//!
//! Used by the RSA-OAEP path where the CEK is ephemeral (never stored in the KMS DB).
//! The `dir` path delegates to the KMIP Encrypt/Decrypt pipeline instead.

use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use zeroize::Zeroizing;

use super::{CryptoApiError, JoseEncAlgorithm, cek_size_bytes};

/// AES-GCM IV length in bytes (96 bits per NIST SP 800-38D).
const AES_GCM_IV_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes (128 bits per RFC 7518 §5.1).
const AES_GCM_TAG_LEN: usize = 16;

/// Output of `aes_gcm_encrypt`: ciphertext, IV, and authentication tag.
pub(crate) struct AesGcmOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Select the OpenSSL `Cipher` for the given content-encryption algorithm.
fn cipher_for_enc(enc: JoseEncAlgorithm) -> Cipher {
    match enc {
        JoseEncAlgorithm::A128GCM => Cipher::aes_128_gcm(),
        JoseEncAlgorithm::A192GCM => Cipher::aes_192_gcm(),
        JoseEncAlgorithm::A256GCM => Cipher::aes_256_gcm(),
    }
}

/// Generate a random CEK of the appropriate size for the given `enc` algorithm.
///
/// The returned key is wrapped in `Zeroizing` so it is wiped on drop.
pub(crate) fn generate_cek(enc: JoseEncAlgorithm) -> Result<Zeroizing<Vec<u8>>, CryptoApiError> {
    let len = cek_size_bytes(enc);
    let mut cek = Zeroizing::new(vec![0_u8; len]);
    rand_bytes(&mut cek).map_err(|e| {
        CryptoApiError::InternalError(format!("Failed to generate random CEK: {e}"))
    })?;
    Ok(cek)
}

/// AES-GCM encrypt using an ephemeral CEK.
///
/// Returns `(ciphertext, iv, tag)` where:
/// - `iv` is a freshly generated 12-byte random nonce
/// - `tag` is the 16-byte authentication tag
pub(crate) fn aes_gcm_encrypt(
    cek: &[u8],
    enc: JoseEncAlgorithm,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AesGcmOutput, CryptoApiError> {
    let cipher = cipher_for_enc(enc);

    // Validate CEK length
    let expected_len = cek_size_bytes(enc);
    if cek.len() != expected_len {
        return Err(CryptoApiError::InternalError(format!(
            "CEK length mismatch: expected {expected_len} bytes for {enc}, got {}",
            cek.len()
        )));
    }

    // Generate random IV
    let mut iv = vec![0_u8; AES_GCM_IV_LEN];
    rand_bytes(&mut iv)
        .map_err(|e| CryptoApiError::InternalError(format!("Failed to generate random IV: {e}")))?;

    // Encrypt
    let mut tag = vec![0_u8; AES_GCM_TAG_LEN];
    let ciphertext = encrypt_aead(cipher, cek, Some(&iv), aad, plaintext, &mut tag)
        .map_err(|e| CryptoApiError::InternalError(format!("AES-GCM encryption failed: {e}")))?;

    Ok(AesGcmOutput {
        ciphertext,
        iv,
        tag,
    })
}

/// AES-GCM decrypt using the recovered CEK.
///
/// Returns the plaintext on success, or an error if the authentication tag does not verify.
pub(crate) fn aes_gcm_decrypt(
    cek: &[u8],
    enc: JoseEncAlgorithm,
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoApiError> {
    let cipher = cipher_for_enc(enc);

    // Validate IV length (must be 12 bytes for JOSE GCM)
    if iv.len() != AES_GCM_IV_LEN {
        return Err(CryptoApiError::BadRequest(format!(
            "Invalid IV length: expected {AES_GCM_IV_LEN} bytes, got {}",
            iv.len()
        )));
    }

    // Validate tag length (must be 16 bytes for JOSE GCM)
    if tag.len() != AES_GCM_TAG_LEN {
        return Err(CryptoApiError::BadRequest(format!(
            "Invalid authentication tag length: expected {AES_GCM_TAG_LEN} bytes, got {}",
            tag.len()
        )));
    }

    let plaintext = decrypt_aead(cipher, cek, Some(iv), aad, ciphertext, tag).map_err(|e| {
        tracing::debug!("AES-GCM decryption failed (expected for implicit rejection): {e}");
        CryptoApiError::DecryptionFailed
    })?;

    Ok(Zeroizing::new(plaintext))
}

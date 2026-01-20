//! These functions use OpenSSL to simulate some cloud provider HSM operations
//! for testing purposes. Using OpenSSL avoids using vendor-specific SDKs in tests
//! and keeps the tests independent from KMS key generation/export actions.
use cosmian_kms_crypto::reexport::cosmian_crypto_core::CsRng;
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use sha2::digest::crypto_common::rand_core::{RngCore, SeedableRng};

use crate::error::{KmsCliError, result::KmsCliResult};

/// Generate RSA keypair using OpenSSL (random size from 2048, 3072, or 4096 bits).
pub(crate) fn generate_rsa_keypair() -> KmsCliResult<(PKey<Private>, PKey<Public>)> {
    let key_sizes = [2048, 3072, 4096];
    let mut rng = CsRng::from_entropy();
    let bits = key_sizes[(rng.next_u32() as usize) % key_sizes.len()];

    let rsa = Rsa::generate(bits)
        .map_err(|e| KmsCliError::Default(format!("Failed to generate RSA key: {e}")))?;
    let private_key = PKey::from_rsa(rsa.clone())
        .map_err(|e| KmsCliError::Default(format!("Failed to build private key: {e}")))?;
    let public_key = PKey::from_rsa(
        Rsa::from_public_components(
            rsa.n()
                .to_owned()
                .map_err(|e| KmsCliError::Default(format!("Failed to clone modulus: {e}")))?,
            rsa.e()
                .to_owned()
                .map_err(|e| KmsCliError::Default(format!("Failed to clone exponent: {e}")))?,
        )
        .map_err(|e| KmsCliError::Default(format!("Failed to build public RSA key: {e}")))?,
    )
    .map_err(|e| KmsCliError::Default(format!("Failed to build public key: {e}")))?;

    Ok((private_key, public_key))
}

/// Unwrap (decrypt) the given ciphertext using `RSA_AES_KEY_WRAP_SHA_1`
/// This is a two-step unwrapping process:
/// 1. RSA-OAEP with SHA-1 unwraps the ephemeral AES key
/// 2. AES Key Wrap (RFC 5649) unwraps the actual key material
pub(crate) fn rsa_aes_key_wrap_sha1_unwrap(
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // The ciphertext structure is: [RSA-encrypted AES key | AES-wrapped key material]
    // RSA-encrypted part size equals the RSA key size in bytes
    let rsa_key_size = private_key.size();

    if ciphertext.len() <= rsa_key_size {
        return Err("Ciphertext too short for RSA_AES_KEY_WRAP".into());
    }

    // Split the ciphertext into RSA-encrypted AES key and AES-wrapped key material
    let (encrypted_aes_key, wrapped_key_material) = ciphertext.split_at(rsa_key_size);

    // Step 1: Unwrap the ephemeral AES key using RSA-OAEP with SHA-1
    let aes_key = rsaes_oaep_sha1_unwrap(encrypted_aes_key, private_key)?;

    // Step 2: Unwrap the key material using AES Key Wrap (RFC 5649)
    let unwrapped_key = aes_key_unwrap(wrapped_key_material, &aes_key)?;
    Ok(unwrapped_key)
}

/// Unwrap (decrypt) the given ciphertext using RSAES-OAEP with SHA-256
/// This replaces the AWS KMS Import key material step for testing purposes.
/// The aws API equivalent command (on cli) is:
/// ```sh
/// aws kms import-key-material --key-id <YOUR_EXTERNAL_KEY_ID> \
/// --encrypted-key-material fileb://<YOUR_WRAPPED_KEY> \
/// --import-token fileb://<YOUR_TOKEN> \
/// --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE
/// ```
pub(crate) fn rsaes_oaep_sha256_unwrap(
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decrypter = Decrypter::new(private_key)?;

    // Set OAEP padding with SHA-256
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;

    // Calculate buffer size
    let buffer_len = decrypter.decrypt_len(ciphertext)?;
    let mut decrypted = vec![0_u8; buffer_len];

    // Decrypt
    let decrypted_len = decrypter.decrypt(ciphertext, &mut decrypted)?;
    decrypted.truncate(decrypted_len);

    Ok(decrypted)
}

/// Unwrap (decrypt) the given ciphertext using RSAES-OAEP with SHA-1
/// This replaces the AWS KMS Import key material step for testing purposes.
pub(crate) fn rsaes_oaep_sha1_unwrap(
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decrypter = Decrypter::new(private_key)?;

    // Set OAEP padding with SHA-1
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;

    // Calculate buffer size
    let buffer_len = decrypter.decrypt_len(ciphertext)?;
    let mut decrypted = vec![0_u8; buffer_len];

    // Decrypt
    let decrypted_len = decrypter.decrypt(ciphertext, &mut decrypted)?;
    decrypted.truncate(decrypted_len);

    Ok(decrypted)
}

/// AES Key Unwrap with Padding (RFC 5649) using OpenSSL
fn aes_key_unwrap(ciphertext: &[u8], kek: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const AES_WRAP_BLOCK_SIZE: usize = 8;

    // RFC 5649 requires ciphertext to be at least 16 bytes and a multiple of 8 bytes
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(AES_WRAP_BLOCK_SIZE) {
        return Err("Invalid ciphertext size for AES Key Unwrap".into());
    }

    // Select cipher based on KEK size
    let cipher: &CipherRef = match kek.len() {
        16 => Cipher::aes_128_wrap_pad(),
        24 => Cipher::aes_192_wrap_pad(),
        32 => Cipher::aes_256_wrap_pad(),
        _ => {
            return Err(format!(
                "Invalid KEK size: {} bytes. Expected 16, 24, or 32",
                kek.len()
            )
            .into());
        }
    };
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(cipher), Some(kek), None)?;

    // Allocate output buffer with extra space (defensive maneuver - the final result will be truncated to the actual size)
    let mut plaintext = vec![0_u8; ciphertext.len() + 16];

    let mut written = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
    written += ctx.cipher_final(&mut plaintext[written..])?;

    // Truncate to actual output size
    plaintext.truncate(written);

    Ok(plaintext)
}

/// Unwrap (decrypt) the given ciphertext using `RSA_AES_KEY_WRAP_SHA_256`
/// This is a two-step unwrapping process:
/// 1. RSA-OAEP with SHA-256 unwraps the ephemeral AES key
/// 2. AES Key Wrap (RFC 5649) unwraps the actual key material
pub(crate) fn rsa_aes_key_wrap_sha256_unwrap(
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // The ciphertext structure is: [RSA-encrypted AES key | AES-wrapped key material]
    // RSA-encrypted part size equals the RSA key size in bytes
    let rsa_key_size = private_key.size();

    if ciphertext.len() <= rsa_key_size {
        return Err("Ciphertext too short for RSA_AES_KEY_WRAP".into());
    }

    // Split the ciphertext into RSA-encrypted AES key and AES-wrapped key material
    let (encrypted_aes_key, wrapped_key_material) = ciphertext.split_at(rsa_key_size);

    // Step 1: Unwrap the ephemeral AES key using RSA-OAEP with SHA-256
    let aes_key = rsaes_oaep_sha256_unwrap(encrypted_aes_key, private_key)?;

    // Step 2: Unwrap the key material using AES Key Wrap (RFC 5649)
    let unwrapped_key = aes_key_unwrap(wrapped_key_material, &aes_key)?;

    Ok(unwrapped_key)
}

//! AWS KMS is a managed service that can't be run locally for tests. By its design, private key materials never leave the AWS HSM, which makes it even harder to make tests that do not involve
//! actual calls to external infrastructure. Therefore, to verify the correct behavior of the AWS KMS BYOK import and export commands, we will unwrap using openssl.
//! As long as we can trust AWS KMS to behave correctly, we can consider these functions viable to verify the unwrapping process.
//!
//! If ever E2E tests with AWS KMS are to be implemented, simply edit the calls to the functions below to calls to AWS KMS `import-key-material` command.
use cosmian_kms_crypto::reexport::cosmian_crypto_core::CsRng;
use jwt_simple::reexports::rand::SeedableRng;
use jwt_simple::reexports::rand::seq::SliceRandom as _;
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use openssl::{encrypt::Decrypter, hash::MessageDigest};

use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};

/// Generate RSA keypair using openssl (random size from 2048, 3072, or 4096 bits)
/// This replaces the AWS KMS keypair generation for testing purposes.
/// The aws API equivalent command (on cli) is:
/// ```sh
///  aws kms get-parameters-for-import \
/// --key-id <YOUR_EXTERNAL_KEY_ID> \
/// --wrapping-algorithm RSAES_OAEP_SHA_256 \
/// --wrapping-key-spec RSA_3072 # or RSA_2048 or RSA_4096
/// ```
pub(crate) fn generate_rsa_keypair()
-> Result<(PKey<Private>, PKey<Public>), Box<dyn std::error::Error>> {
    // Randomly select key size from AWS-supported sizes
    let key_sizes = [2048, 3072, 4096];
    let mut rng = CsRng::from_entropy();
    let bits = *key_sizes.choose(&mut rng).expect("key_sizes is not empty");

    let rsa = Rsa::generate(bits)?;

    let private_key = PKey::from_rsa(rsa.clone())?;
    let public_key = PKey::from_rsa(Rsa::from_public_components(
        rsa.n().to_owned()?,
        rsa.e().to_owned()?,
    )?)?;

    Ok((private_key, public_key))
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
        24 => Cipher::aes_192_wrap_pad(), // TODO delete those after fixingh the bug
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

/// Generate SM2 keypair using OpenSSL
/// This replaces the chinese AWS KMS keypair generation for testing purposes.
#[cfg(feature = "non-fips")]
pub(crate) fn generate_sm2_keypair()
-> Result<(PKey<Private>, PKey<Public>), Box<dyn std::error::Error>> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;

    let group = EcGroup::from_curve_name(Nid::SM2)?;

    // Generate EC key on SM2 curve
    let ec_key = EcKey::generate(&group)?;

    // Convert to PKey
    let private_key = PKey::from_ec_key(ec_key.clone())?;

    // Extract public key
    let public_ec_key = EcKey::from_public_key(&group, ec_key.public_key())?;
    let public_key = PKey::from_ec_key(public_ec_key)?;

    Ok((private_key, public_key))
}

/// Unwrap (decrypt) the given ciphertext using SM2PKE (SM2 Public Key Encryption)
/// SM2PKE is a Chinese national standard encryption algorithm used in AWS China regions.
/// This replaces the AWS KMS Import key material step for testing purposes.
///
/// Note: SM2 support requires OpenSSL 1.1.1+ compiled with SM2 support.
/// This is typically available in non-FIPS mode only.
#[cfg(feature = "non-fips")]
pub(crate) fn sm2pke_unwrap(
    ciphertext: &[u8],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Verify the key is an SM2 key

    use openssl::pkey_ctx::PkeyCtx;
    if private_key.id() != openssl::pkey::Id::SM2 {
        return Err("Private key is not an SM2 key".into());
    }

    // Create decryption context
    let mut ctx = PkeyCtx::new(private_key)?;
    ctx.decrypt_init()?;

    // Calculate buffer size for decryption
    let buffer_len = ctx.decrypt(ciphertext, None)?;
    let mut plaintext = vec![0_u8; buffer_len];

    // Perform decryption
    let plaintext_len = ctx.decrypt(ciphertext, Some(&mut plaintext))?;
    plaintext.truncate(plaintext_len);

    Ok(plaintext)
}

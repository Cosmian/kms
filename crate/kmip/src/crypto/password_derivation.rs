// This file exists to standardize key-derivation across all KMS crates
#[cfg(not(feature = "fips"))]
use argon2::Argon2;
#[cfg(feature = "fips")]
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

use super::secret::Secret;
use crate::error::KmipError;
#[cfg(feature = "fips")]
use crate::kmip_bail;

/// Minimum random salt size in bytes to use when deriving keys.
pub const FIPS_MIN_SALT_SIZE: usize = 16;

#[cfg(feature = "fips")]
/// Output size in bits of the hash function used in PBKDF2.
pub const FIPS_HLEN: usize = 512;
#[cfg(feature = "fips")]
/// Minimum key length in bits to be derived in FIPS mode.
pub const FIPS_MIN_KLEN: usize = 112;
#[cfg(feature = "fips")]
/// Max key length in bits authorized is (2^32 - 1) x hLen.
/// Source: NIST.FIPS.800-132 - Section 5.3.
pub const FIPS_MAX_KLEN: usize = ((1 << 32) - 1) * FIPS_HLEN;

#[cfg(feature = "fips")]
/// OWASP recommended parameter for SHA-512 chosen following NIST.FIPS.800-132
/// recommendations.
pub const FIPS_MIN_ITER: usize = 210_000;

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(feature = "fips")]
pub fn derive_key_from_password<const LENGTH: usize>(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    password: &[u8],
) -> Result<Secret<LENGTH>, KmipError> {
    // Check requested key length converted in bits is in the authorized bounds.
    if LENGTH * 8 < FIPS_MIN_KLEN || LENGTH * 8 > FIPS_MAX_KLEN {
        kmip_bail!("Password derivation error: wrong output length argument, got {LENGTH}")
    }

    let mut output_key_material = Secret::<LENGTH>::new();

    pbkdf2_hmac(
        password,
        salt,
        FIPS_MIN_ITER,
        MessageDigest::sha512(),
        output_key_material.as_mut(),
    )?;

    Ok(output_key_material)
}

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(not(feature = "fips"))]
pub fn derive_key_from_password<const LENGTH: usize>(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    password: &[u8],
) -> Result<Secret<LENGTH>, KmipError> {
    let mut output_key_material = Secret::<LENGTH>::new();

    Argon2::default()
        .hash_password_into(password, salt, output_key_material.as_mut())
        .map_err(|e| KmipError::Derivation(e.to_string()))?;

    Ok(output_key_material)
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_password_derivation() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let salt = b"rediswithfindex_";
    let my_weak_password = b"doglover1234".to_vec();
    let secure_mk = derive_key_from_password::<32>(salt, &my_weak_password).unwrap();

    assert_eq!(secure_mk.len(), 32);
}

#[test]
#[allow(clippy::unwrap_used)]
#[cfg(feature = "fips")]
fn test_password_derivation_bad_size() {
    const BIG_KEY_LENGTH: usize = (((1 << 32) - 1) * 512) / 8 + 1;
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let salt = b"rediswithfindex_";
    let my_weak_password = b"123princ3ss".to_vec();
    let secure_mk_res = derive_key_from_password::<13>(salt, &my_weak_password);

    secure_mk_res.unwrap_err();

    let secure_mk_res = derive_key_from_password::<BIG_KEY_LENGTH>(salt, &my_weak_password);

    secure_mk_res.unwrap_err();
}

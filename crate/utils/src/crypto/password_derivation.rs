// This file exists to standardize key-derivation across all KMS crates
#[cfg(not(feature = "fips"))]
use argon2::Argon2;
use openssl::rand::rand_bytes;
#[cfg(feature = "fips")]
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

use crate::error::KmipUtilsError;
#[cfg(feature = "fips")]
use crate::kmip_utils_bail;

const FIPS_MIN_SALT_SIZE: usize = 16;
#[cfg(feature = "fips")]
const FIPS_MIN_KLEN: usize = 14;
#[cfg(feature = "fips")]
const FIPS_HLEN_BITS: usize = 256;
#[cfg(feature = "fips")]
/// OWASP recommended parameter for SHA-512 chosen following NIST.FIPS.800-132
/// recommendations.
const FIPS_MIN_ITER: usize = 210_000;

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(feature = "fips")]
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<[u8; LENGTH], KmipUtilsError> {
    if LENGTH < FIPS_MIN_KLEN || LENGTH * 8 > ((1 << 32) - 1) * FIPS_HLEN_BITS {
        kmip_utils_bail!(
            "Password derivation error: wrong output length argument, got {}",
            LENGTH,
        )
    }

    let mut output_key_material = [0u8; LENGTH];

    // Generate 128 bits of random salt.
    let mut salt = vec![0u8; FIPS_MIN_SALT_SIZE];
    rand_bytes(&mut salt)?;

    pbkdf2_hmac(
        password,
        &salt,
        FIPS_MIN_ITER,
        MessageDigest::sha512(),
        &mut output_key_material,
    )?;

    Ok(output_key_material)
}

#[cfg(not(feature = "fips"))]
/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<[u8; LENGTH], KmipUtilsError> {
    let mut output_key_material = [0u8; LENGTH];

    // Generate 128 bits of random salt
    let mut salt = vec![0u8; FIPS_MIN_SALT_SIZE];
    rand_bytes(&mut salt)?;

    Argon2::default()
        .hash_password_into(password, &salt, &mut output_key_material)
        .map_err(|e| KmipUtilsError::Derivation(e.to_string()))?;

    Ok(output_key_material)
}

#[test]
fn test_password_derivation() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let my_weak_password = "doglover1234".as_bytes().to_vec();
    let secure_mk = derive_key_from_password::<32>(&my_weak_password).unwrap();

    assert_eq!(secure_mk.len(), 32);
}

#[test]
#[cfg(feature = "fips")]
fn test_password_derivation_bad_size() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let my_weak_password = "123princ3ss".as_bytes().to_vec();
    let secure_mk_res = derive_key_from_password::<13>(&my_weak_password);

    assert!(secure_mk_res.is_err());
}

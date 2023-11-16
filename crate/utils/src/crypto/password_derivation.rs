// This file exists to standardize key-derivation across all KMS crates
use argon2::Argon2;
use cloudproof::reexport::crypto_core::{FixedSizeCBytes, SymmetricKey};
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac, rand::rand_bytes};

use crate::{error::KmipUtilsError, kmip_utils_bail};

/// The salt to use when deriving passwords in the KMS crate with Argon2.
pub const KMS_ARGON2_SALT: &[u8] = b"Default salt used in KMS crates";

const FIPS_MIN_KLEN: usize = 14;
const FIPS_MIN_SALT_SIZE: usize = 16;
const FIPS_HLEN_BITS: usize = 256;
/// Arbitrary parameter chosen following NIST.FIPS.800-132 recommandations.
const FIPS_MIN_ITER: usize = 210_000;

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and SHA512 in
/// FIPS mode.
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<SymmetricKey<LENGTH>, KmipUtilsError> {
    let mut output_key_material = [0u8; LENGTH];

    if cfg!(feature = "fips") {
        if LENGTH < FIPS_MIN_KLEN || LENGTH * 8 > ((1 << 32) - 1) * FIPS_HLEN_BITS {
            kmip_utils_bail!(
                "Password derivation error: wrong output length argument, got {}",
                LENGTH,
            )
        }

        let mut salt = vec![0u8; FIPS_MIN_SALT_SIZE];
        rand_bytes(&mut salt)?;

        pbkdf2_hmac(
            password,
            &salt,
            FIPS_MIN_ITER,
            MessageDigest::sha512(),
            &mut output_key_material,
        )?;
    } else {
        Argon2::default()
            .hash_password_into(password, KMS_ARGON2_SALT, &mut output_key_material)
            .map_err(|e| KmipUtilsError::Derivation(e.to_string()))?;
    }

    // TODO Waiting for fix in crypto_core were from() should be implemented.
    let sk = SymmetricKey::try_from_bytes(output_key_material)?;
    Ok(sk)
}

#[test]
fn test_password_derivation() {
    let my_weak_password = "doglover1234".as_bytes().to_vec();
    let secure_mk = derive_key_from_password::<32>(&my_weak_password).unwrap();

    assert_eq!(secure_mk.len(), 32);
}

#[cfg(feature = "fips")]
#[test]
fn test_password_derivation_bad_size() {
    let my_weak_password = "splintorage".as_bytes().to_vec();
    let secure_mk = derive_key_from_password::<13>(&my_weak_password);

    assert!(secure_mk.is_err());
}

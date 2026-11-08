// This file exists to standardize key-derivation across all KMS crates
#[cfg(not(feature = "non-fips"))]
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

use super::secret::Secret;
#[cfg(not(feature = "non-fips"))]
use crate::crypto_bail;
use crate::error::CryptoError;

/// Minimum random salt size in bytes to use when deriving keys.
pub const FIPS_MIN_SALT_SIZE: usize = 16;

/// Output size in bits of the hash function used in PBKDF2.
pub const FIPS_HLEN: usize = 512;

/// Minimum key length in bits to be derived in FIPS mode.
pub const FIPS_MIN_KLEN: usize = 112;

/// Max key length in bits authorized is (2^32 - 1) x hLen.
/// Source: NIST.FIPS.800-132 - Section 5.3.
pub const FIPS_MAX_KLEN: usize = ((1 << 32) - 1) * FIPS_HLEN;

/// OWASP recommended parameter for SHA-512 chosen following NIST.FIPS.800-132
/// recommendations.
pub const FIPS_MIN_ITER: usize = 210_000;

/// Derive a key into a LENGTH bytes key using Argon2id (OpenSSL) by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(not(feature = "non-fips"))]
pub fn derive_key_from_password<const LENGTH: usize>(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    password: &[u8],
) -> Result<Secret<LENGTH>, CryptoError> {
    // Check requested key length converted in bits is in the authorized bounds.
    if LENGTH * 8 < FIPS_MIN_KLEN || LENGTH * 8 > FIPS_MAX_KLEN {
        crypto_bail!("Password derivation error: wrong output length argument, got {LENGTH}")
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

/// Derive a key into a LENGTH bytes key using Argon2id (OpenSSL) by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(feature = "non-fips")]
pub fn derive_key_from_password<const LENGTH: usize>(
    salt: &[u8; FIPS_MIN_SALT_SIZE],
    password: &[u8],
) -> Result<Secret<LENGTH>, CryptoError> {
    let mut okm = Secret::<LENGTH>::new();
    argon2id(password, salt, okm.as_mut())?;
    Ok(okm)
}

/// Argon2id (RFC 9106) through OpenSSL's `EVP_KDF`, with the parameters of the former
/// `argon2` crate defaults: m=19456 KiB, t=2, p=1.
///
/// Raw FFI because `openssl::kdf::argon2id` is gated on `ossl320`, which is off when
/// `openssl-sys` builds against 3.0 headers; only `ossl300` is needed here.
#[cfg(feature = "non-fips")]
#[expect(
    unsafe_code,
    reason = "raw EVP_KDF FFI; openssl::kdf::argon2id is gated on ossl320"
)]
pub(crate) fn argon2id(password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    use std::{ffi::c_uint, ptr};

    use openssl::error::ErrorStack;

    let derivation_error = || CryptoError::Derivation(format!("Argon2id: {}", ErrorStack::get()));

    // SAFETY: the algorithm name is a NUL-terminated static; null ctx/properties select defaults.
    let kdf =
        unsafe { openssl_sys::EVP_KDF_fetch(ptr::null_mut(), c"ARGON2ID".as_ptr(), ptr::null()) };
    if kdf.is_null() {
        return Err(derivation_error());
    }
    // SAFETY: `kdf` is a live EVP_KDF; the context holds its own reference, so it can be freed.
    let ctx = unsafe {
        let ctx = openssl_sys::EVP_KDF_CTX_new(kdf);
        openssl_sys::EVP_KDF_free(kdf);
        ctx
    };
    if ctx.is_null() {
        return Err(derivation_error());
    }

    let mut iter: c_uint = 2;
    let mut lanes: c_uint = 1;
    let mut memcost: c_uint = 19_456;
    let mut threads: c_uint = 1;
    let mut size = match c_uint::try_from(out.len()) {
        Ok(size) => size,
        Err(e) => {
            // SAFETY: `ctx` is a live EVP_KDF_CTX, freed exactly once.
            unsafe { openssl_sys::EVP_KDF_CTX_free(ctx) };
            return Err(CryptoError::Derivation(format!(
                "Argon2id: output length: {e}"
            )));
        }
    };

    // SAFETY: every buffer outlives the derive call (OpenSSL only reads `pass`/`salt` and the
    // uint values), the params array is terminated by `OSSL_PARAM_construct_end`, `ctx` is a live
    // EVP_KDF_CTX freed exactly once, and `out` is writable for `out.len()` bytes.
    let rc = unsafe {
        let params = [
            openssl_sys::OSSL_PARAM_construct_octet_string(
                c"pass".as_ptr(),
                password.as_ptr().cast_mut().cast(),
                password.len(),
            ),
            openssl_sys::OSSL_PARAM_construct_octet_string(
                c"salt".as_ptr(),
                salt.as_ptr().cast_mut().cast(),
                salt.len(),
            ),
            openssl_sys::OSSL_PARAM_construct_uint(c"iter".as_ptr(), &raw mut iter),
            openssl_sys::OSSL_PARAM_construct_uint(c"lanes".as_ptr(), &raw mut lanes),
            openssl_sys::OSSL_PARAM_construct_uint(c"memcost".as_ptr(), &raw mut memcost),
            openssl_sys::OSSL_PARAM_construct_uint(c"threads".as_ptr(), &raw mut threads),
            openssl_sys::OSSL_PARAM_construct_uint(c"size".as_ptr(), &raw mut size),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        let rc = openssl_sys::EVP_KDF_derive(ctx, out.as_mut_ptr(), out.len(), params.as_ptr());
        openssl_sys::EVP_KDF_CTX_free(ctx);
        rc
    };
    if rc <= 0 {
        return Err(derivation_error());
    }
    Ok(())
}

#[test]
fn test_password_derivation() {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    openssl::provider::Provider::load(None, "fips").unwrap();

    let salt = b"rediswithfindex_";
    let my_weak_password = b"doglover1234".to_vec();
    let secure_mk = derive_key_from_password::<32>(salt, &my_weak_password).unwrap();

    assert_eq!(secure_mk.len(), 32);
}

/// Pins the Argon2id output: persisted data (Redis-findex master key, wrapped keys) depends on it.
#[test]
#[cfg(feature = "non-fips")]
fn test_password_derivation_argon2id_kat() {
    let salt = b"rediswithfindex_";
    let password = b"doglover1234";
    assert_eq!(
        hex::encode(&*derive_key_from_password::<32>(salt, password).unwrap()),
        "19aca4e7c8f8859877ec15b354b8a807669dfb823ece05efbc541de45c6b75ac"
    );
    assert_eq!(
        hex::encode(&*derive_key_from_password::<64>(salt, password).unwrap()),
        "3c3fde7d94991f954c1e9fe8c82ac5ac7b09df9cb932e6643b1024c39d6be89bd08798907ca42a1b76f0abadafd266f69791f5e9e584dd20d88e3c13bf83c71e"
    );
}

#[test]
#[cfg(all(not(feature = "non-fips"), not(target_os = "windows")))]
fn test_password_derivation_bad_size() {
    const BIG_KEY_LENGTH: usize = (((1 << 32) - 1) * 512) / 8 + 1;
    let salt = b"rediswithfindex_";
    let my_weak_password = b"123princ3ss".to_vec();
    let secure_mk_res = derive_key_from_password::<13>(salt, &my_weak_password);

    secure_mk_res.unwrap_err();

    let secure_mk_res = derive_key_from_password::<BIG_KEY_LENGTH>(salt, &my_weak_password);

    secure_mk_res.unwrap_err();
}

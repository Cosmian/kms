//! In a FIPS-mode build, the DRBGs behind `KmsRng` must be served by the FIPS provider, not by
//! the default provider (NIST SP 800-90A r1 / FIPS 140-3: only the validated module's DRBG may
//! produce key material). This is a regression test for an `openssl.cnf` that also activated the
//! default provider, which silently moved `RAND_bytes` out of the FIPS module.
#![cfg(not(feature = "non-fips"))]
#![allow(
    unsafe_code,
    missing_docs,
    clippy::expect_used,
    clippy::as_conversions,
    clippy::as_underscore,
    clippy::fn_to_numeric_cast_any
)]

use std::ffi::{CStr, c_char, c_uint, c_void};

use cosmian_kms_crypto::crypto::KmsRng;

unsafe extern "C" {
    fn RAND_get0_primary(ctx: *mut c_void) -> *mut c_void;
    fn RAND_get0_public(ctx: *mut c_void) -> *mut c_void;
    fn RAND_get0_private(ctx: *mut c_void) -> *mut c_void;
    fn EVP_RAND_CTX_get0_rand(ctx: *mut c_void) -> *mut c_void;
    fn EVP_RAND_get0_provider(rand: *mut c_void) -> *mut c_void;
    fn OSSL_PROVIDER_get0_name(provider: *const c_void) -> *const c_char;
    fn EVP_RAND_get_strength(ctx: *mut c_void) -> c_uint;
}

#[test]
fn kms_rng_is_served_by_the_fips_provider_drbg() {
    // Same environment the crate's build script configures; absent under Nix, where the
    // runtime environment already provides it.
    // SAFETY: single test in this binary, no other thread reads the environment yet.
    unsafe {
        if let Some(conf) = option_env!("OPENSSL_CONF") {
            std::env::set_var("OPENSSL_CONF", conf);
        }
        if let Some(modules) = option_env!("OPENSSL_MODULES") {
            std::env::set_var("OPENSSL_MODULES", modules);
        }
    }
    // Instantiate the DRBG hierarchy through KmsRng itself.
    let rng = KmsRng::new();
    rng.random_vec(32).expect("private DRBG");
    rng.fill_public_bytes(&mut [0_u8; 32]).expect("public DRBG");

    for (name, get) in [
        (
            "primary",
            RAND_get0_primary as unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        ),
        ("public", RAND_get0_public),
        ("private", RAND_get0_private),
    ] {
        // SAFETY: the DRBG contexts are owned by OpenSSL and outlive this test; every pointer is
        // NULL-checked before use, and provider names are NUL-terminated static strings.
        let (provider, strength) = unsafe {
            let ctx = get(std::ptr::null_mut());
            assert!(!ctx.is_null(), "{name} DRBG not instantiated");
            let provider =
                OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(ctx)));
            (
                CStr::from_ptr(provider).to_string_lossy().into_owned(),
                EVP_RAND_get_strength(ctx),
            )
        };
        assert_eq!(
            provider, "fips",
            "{name} DRBG is not served by the FIPS provider"
        );
        assert!(strength >= 256, "{name} DRBG strength {strength} < 256");
    }
}

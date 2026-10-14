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
use foreign_types::ForeignTypeRef;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
};

unsafe extern "C" {
    fn RAND_get0_primary(ctx: *mut c_void) -> *mut c_void;
    fn RAND_get0_public(ctx: *mut c_void) -> *mut c_void;
    fn RAND_get0_private(ctx: *mut c_void) -> *mut c_void;
    fn EVP_RAND_CTX_get0_rand(ctx: *mut c_void) -> *mut c_void;
    fn EVP_RAND_get0_provider(rand: *mut c_void) -> *mut c_void;
    fn OSSL_PROVIDER_get0_name(provider: *const c_void) -> *const c_char;
    fn EVP_RAND_get_strength(ctx: *mut c_void) -> c_uint;
    fn EVP_PKEY_get0_provider(pkey: *const c_void) -> *const c_void;
}

/// Assert the primary, public and private DRBGs are served by the FIPS provider at >= 256 bits.
fn assert_drbgs_are_fips(when: &str) {
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
            assert!(!ctx.is_null(), "{name} DRBG not instantiated ({when})");
            let provider =
                OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(ctx)));
            (
                CStr::from_ptr(provider).to_string_lossy().into_owned(),
                EVP_RAND_get_strength(ctx),
            )
        };
        assert_eq!(
            provider, "fips",
            "{name} DRBG is not served by the FIPS provider ({when})"
        );
        assert!(
            strength >= 256,
            "{name} DRBG strength {strength} < 256 ({when})"
        );
    }
}

/// Name of the provider whose key management generated `pkey`, or `None` for a legacy
/// (non-provider) key such as those built from `Rsa::generate` / `EcKey::generate`.
fn keygen_provider(pkey: &PKeyRef<Private>) -> Option<String> {
    // SAFETY: `pkey` is a valid `EVP_PKEY`; the provider is NULL-checked before use and its name
    // is a NUL-terminated static string.
    unsafe {
        let provider = EVP_PKEY_get0_provider(pkey.as_ptr().cast_const().cast());
        if provider.is_null() {
            return None;
        }
        let name = OSSL_PROVIDER_get0_name(provider);
        assert!(!name.is_null(), "provider has no name");
        Some(CStr::from_ptr(name).to_string_lossy().into_owned())
    }
}

/// RSA, EC and Curve25519 key generation cannot be routed through `KmsRng`: OpenSSL draws from
/// its own default DRBG. Generate one key of each family and check that doing so neither fails nor
/// moves the hierarchy out of the FIPS provider; provider-backed keys must also come from the FIPS
/// provider's key management.
fn generate_implicit_openssl_keys() {
    let mut keys: Vec<(&str, PKey<Private>)> = vec![
        (
            "RSA-2048",
            PKey::from_rsa(Rsa::generate(2048).expect("RSA keygen")).expect("RSA pkey"),
        ),
        (
            "RSA-3072",
            PKey::from_rsa(Rsa::generate(3072).expect("RSA keygen")).expect("RSA pkey"),
        ),
        ("X25519", PKey::generate_x25519().expect("X25519 keygen")),
        ("Ed25519", PKey::generate_ed25519().expect("Ed25519 keygen")),
    ];
    for (name, nid) in [
        ("P-256", Nid::X9_62_PRIME256V1),
        ("P-384", Nid::SECP384R1),
        ("P-521", Nid::SECP521R1),
    ] {
        let group = EcGroup::from_curve_name(nid).expect("EC group");
        keys.push((
            name,
            PKey::from_ec_key(EcKey::generate(&group).expect("EC keygen")).expect("EC pkey"),
        ));
    }
    for (name, pkey) in &keys {
        if let Some(provider) = keygen_provider(pkey) {
            assert_eq!(
                provider, "fips",
                "{name} key generation is not served by the FIPS provider"
            );
        }
    }
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

    assert_drbgs_are_fips("after KmsRng use");
    generate_implicit_openssl_keys();
    assert_drbgs_are_fips("after RSA/EC/Curve25519 key generation");
}

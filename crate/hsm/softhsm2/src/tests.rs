//! These tests  require a connection to a working HSM and are gated behind the `softhsm2` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password):
//! ```
//! HSM_USER_PASSWORD=12345678 cargo test --target x86_64-unknown-linux-gnu --features softhsm2 -- tests::test_hsm_softhsm2_all
//! ```
use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    HResult,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{SOFTHSM2_PKCS11_LIB, SofthsmCapabilityProvider};

const SLOT_ID: usize = 0x01; // SoftHSM2 fallback slot if HSM_SLOT_ID is not set

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("SOFTHSM2_PKCS11_LIB", SOFTHSM2_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        threads: 4,
    })
}

/// To run all the tests, try something like
/// ```sh
///  RUST_LOG=info \
///  HSM_USER_PASSWORD="12345678" \
///  HSM_SLOT_ID=63715018 \
///  cargo test test_hsm_softhsm2_all --features softhsm2 -- --ignored
/// ```
/// WARNING: Initialized tokens will be reassigned to another slot (based on the token serial number)
/// So show the available slots first to determine which slot ID to use
#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_all() -> HResult<()> {
    // Use a single BaseHsm for the entire test to prevent repeated C_Initialize/C_Finalize
    // cycles. Some PKCS#11 native libraries are not safely re-initializable within the same
    // process: repeated load/unload cycles can corrupt internal C state and cause a SIGSEGV.
    let cfg = cfg()?;
    let hsm = shared::instantiate::<SofthsmCapabilityProvider>(&cfg)?;
    shared::get_info(&hsm)?;
    let slot = shared::get_slot::<SofthsmCapabilityProvider>(&hsm, &cfg)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    shared::get_supported_algorithms(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, shared::TEST_RSA_OAEP_DIGEST)?;
    shared::rsa_pkcs_encrypt(&slot)?;
    // `rsa_oaep_encrypt` is deliberately NOT called here: SoftHSM2 rejects CKM_RSA_PKCS_OAEP
    // with explicit mechanism parameters (CKR_ARGUMENTS_BAD, return code 7) — see the
    // comment above `concurrent_sign_does_not_degrade`. Its standalone test fails the same
    // way on this build.
    shared::aes_gcm_encrypt_token_without_iv_generation(&slot)?;
    shared::aes_key_wrap(&slot, cfg.slot_id_for_tests)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::aes_cbc_multi_round(&slot)?;
    shared::aes_cbc_multi_part(&slot)?;
    shared::aes_mac_known_answers(&slot)?;
    shared::aes_gcm_known_answers(&slot)?;
    shared::rsa_pkcs_v15_sign(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::rsa_sign_all_algorithms(&slot)?;
    shared::rsa_pss_sign_all_algorithms(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    #[cfg(feature = "non-fips")]
    shared::eddsa_sign_all_curves(&slot)?;
    // SoftHSM2 2.6.1 rejects CKM_RSA_PKCS_OAEP with explicit mechanism parameters
    // (CKR_ARGUMENTS_BAD/return code 7) regardless of the OAEP hash/MGF digest
    // requested — confirmed for both SHA-256 (see resident_rsa2048_encrypt_oaep_sha256
    // manifest) and SHA-1 (see resident_rsa2048_encrypt_oaep_sha1 manifest) on this
    // SoftHSM2 build. `multi_threaded_rsa` uses RSA-OAEP encrypt/decrypt, so it is
    // skipped entirely here rather than gated by FIPS variant.
    shared::concurrent_sign_does_not_degrade(&slot)?;
    shared::get_key_metadata(&slot)?;
    shared::list_objects(&slot)?;
    shared::search_incompatible_key(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

/// Additive PKCS#11 v3 capability probe (issue #1153).
///
/// `SoftHSM` releases differ in the Cryptoki version they expose. The probe must preserve
/// ordinary PKCS#11 operation and consistently report either no v3 discovery symbol or
/// the interfaces returned by that symbol.
#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_pkcs11_v3_capability_probe_is_additive() -> HResult<()> {
    let cfg = cfg()?;
    let hsm = shared::instantiate::<SofthsmCapabilityProvider>(&cfg)?;

    drop(hsm.hsm_lib().get_info_struct()?);
    let supports_interfaces = hsm.hsm_lib().supports_pkcs11_v3_interfaces();
    let interfaces = hsm.hsm_lib().list_pkcs11_v3_interfaces()?;
    assert_eq!(supports_interfaces, interfaces.is_some());
    if let Some(interfaces) = interfaces {
        assert_ne!(interfaces.len(), 0);
        assert!(
            interfaces
                .iter()
                .all(|interface| !interface.name.is_empty())
        );
    }

    Ok(())
}

/// `SoftHSM2` posing as an HSM that rejects `CKA_SENSITIVE` (AWS/Azure/GCP Cloud HSM, Luna).
struct SofthsmWithoutAesSensitiveProvider;

impl HsmProvider for SofthsmWithoutAesSensitiveProvider {
    fn capabilities() -> HsmCapabilities {
        let mut capabilities = SofthsmCapabilityProvider::capabilities();
        capabilities.aes.supports_sensitive_attribute = false;
        capabilities
    }
}

/// A sensitive AES key must still be generated with `CKA_EXTRACTABLE=false` when the HSM
/// does not accept `CKA_SENSITIVE` (previously left at the token default).
#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_sensitive_aes_key_without_sensitive_attribute() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmWithoutAesSensitiveProvider>(&cfg()?)?;
    shared::generate_aes_key(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_oaep_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_oaep_encrypt(&slot, shared::TEST_RSA_OAEP_DIGEST)
}
// SoftHSM2 FIPS rejects RSA-OAEP-SHA256 (multi_threaded_rsa uses
// TEST_RSA_OAEP_DIGEST = SHA256 in FIPS), so gate behind non-fips where the
// digest is SHA1 (supported).
#[cfg(feature = "non-fips")]
#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, shared::TEST_RSA_OAEP_DIGEST, 4)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_search_incompatible_key() -> HResult<()> {
    let config = &cfg()?;
    let hsm = shared::instantiate::<SofthsmCapabilityProvider>(config)?;
    shared::search_incompatible_key(&hsm, &cfg()?)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_destroy_all() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::destroy_all(&slot)
}

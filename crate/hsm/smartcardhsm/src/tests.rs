//! These tests  require a connection to a working HSM and are gated behind the `softhsm2` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password for the selected slot):
//! ```
//! HSM_USER_PASSWORD=648219 HSM_SLOT_ID=1 cargo test --target x86_64-unknown-linux-gnu --features smartcardhsm -- tests::test_hsm_smartcardhsm_all
//! ```

use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    HResult,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{SMARTCARDHSM_PKCS11_LIB, SmartcardHsmCapabilityProvider};

const SLOT_ID: usize = 0x01; // SmartcardHSM default slot

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("SMARTCARDHSM_PKCS11_LIB", SMARTCARDHSM_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        threads: 2,
    })
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_all() -> HResult<()> {
    // Use a single BaseHsm for the entire test to prevent repeated C_Initialize/C_Finalize
    // cycles. Some PKCS#11 native libraries are not safely re-initializable within the same
    // process: repeated load/unload cycles can corrupt internal C state and cause a SIGSEGV.
    let cfg = cfg()?;
    let hsm = shared::instantiate::<SmartcardHsmCapabilityProvider>(&cfg)?;
    shared::get_info(&hsm)?;
    let slot = shared::get_slot::<SmartcardHsmCapabilityProvider>(&hsm, &cfg)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    shared::get_supported_algorithms(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, shared::TEST_RSA_OAEP_DIGEST)?;
    shared::rsa_pkcs_encrypt(&slot)?;
    shared::rsa_oaep_encrypt(&slot, shared::TEST_RSA_OAEP_DIGEST)?;
    shared::aes_gcm_encrypt(&slot)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::aes_cbc_multi_round(&slot)?;
    shared::rsa_pkcs_v15_sign(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::rsa_sign_all_algorithms(&slot)?;
    shared::rsa_pss_sign_all_algorithms(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    #[cfg(feature = "non-fips")]
    shared::eddsa_sign_all_curves(&slot)?;
    shared::multi_threaded_rsa(&slot, shared::TEST_RSA_OAEP_DIGEST, cfg.threads)?;
    shared::get_key_metadata(&slot)?;
    shared::list_objects(&slot)?;
    shared::search_incompatible_key(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, shared::TEST_RSA_OAEP_DIGEST, 2)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_search_incompatible_key() -> HResult<()> {
    let config = &cfg()?;
    let hsm = shared::instantiate::<SmartcardHsmCapabilityProvider>(config)?;
    shared::search_incompatible_key(&hsm, &cfg()?)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_destroy_all() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::destroy_all(&slot)
}

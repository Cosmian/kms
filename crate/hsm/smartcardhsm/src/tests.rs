//! These tests  require a connection to a working HSM and are gated behind the `softhsm2` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password for the selected slot):
//! ```
//! HSM_USER_PASSWORD=648219 HSM_SLOT_ID=1 cargo test --target x86_64-unknown-linux-gnu --features smartcardhsm -- tests::test_hsm_smartcardhsm_all
//! ```

use std::{collections::HashMap, ptr};

use cosmian_kms_base_hsm::{
    HResult, RsaOaepDigest,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};
use libloading::Library;
use pkcs11_sys::{CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR, CKF_OS_LOCKING_OK, CKR_OK};

use crate::{SMARTCARDHSM_PKCS11_LIB, SmartcardHsmCapabilityProvider};

const SLOT_ID: usize = 0x01; // SmartcardHSM default slot

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("SMARTCARDHSM_PKCS11_LIB", SMARTCARDHSM_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA1),
        threads: 2,
        supports_rsa_wrap: true,
    })
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_all() -> HResult<()> {
    test_hsm_smartcardhsm_get_info()?;
    test_hsm_smartcardhsm_get_mechanisms()?;
    test_hsm_smartcardhsm_get_supported_algorithms()?;
    test_hsm_smartcardhsm_destroy_all()?;
    test_hsm_smartcardhsm_generate_aes_key()?;
    test_hsm_smartcardhsm_generate_rsa_keypair()?;
    //    test_hsm_smartcardhsm_rsa_key_wrap()?; //Not supported
    test_hsm_smartcardhsm_rsa_pkcs_encrypt()?;
    test_hsm_smartcardhsm_rsa_oaep_encrypt()?;
    test_hsm_smartcardhsm_aes_cbc_encrypt()?;
    test_hsm_smartcardhsm_aes_cbc_multi_round_encrypt()?;
    test_hsm_smartcardhsm_multi_threaded_rsa_encrypt_decrypt_test()?;
    test_hsm_smartcardhsm_get_key_metadata()?;
    test_hsm_smartcardhsm_list_objects()?;
    test_hsm_smartcardhsm_search_incompatible_key()?;
    test_hsm_smartcardhsm_destroy_all()?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_low_level_test() -> HResult<()> {
    let cfg = cfg()?;
    let library = unsafe { Library::new(&cfg.lib_path) }?;
    let init = unsafe { library.get::<fn(p_init_args: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;

    let mut p_init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let rv = init(&mut p_init_args as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
    assert_eq!(rv, CKR_OK);

    Ok(())
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_get_info() -> HResult<()> {
    shared::get_info::<SmartcardHsmCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_get_mechanisms() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::get_mechanisms_and_hashes(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_get_supported_algorithms() -> HResult<()> {
    shared::get_supported_algorithms::<SmartcardHsmCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_generate_aes_key() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::generate_aes_key(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_generate_rsa_keypair() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::generate_rsa_keypair(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_rsa_key_wrap() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    // SmartcardHSM supports OAEP SHA1
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA1)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_rsa_pkcs_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_pkcs_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_rsa_oaep_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    // SmartcardHSM supports OAEP SHA1 per get_supported_oaep_hash()
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA1)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_aes_cbc_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::aes_cbc_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_aes_cbc_multi_round_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::aes_cbc_multi_round(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA1, 2)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_list_objects() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::list_objects(&slot)
}

#[test]
#[ignore = "Requires Linux, SmartcardHSM PKCS#11 library, and HSM environment"]
fn test_hsm_smartcardhsm_get_key_metadata() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SmartcardHsmCapabilityProvider>(&cfg()?)?;
    shared::get_key_metadata(&slot)
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

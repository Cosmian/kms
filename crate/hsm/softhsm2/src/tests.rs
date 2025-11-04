//! These tests  require a connection to a working HSM and are gated behind the `softhsm2` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password):
//! ```
//! HSM_USER_PASSWORD=12345678 cargo test --target x86_64-unknown-linux-gnu --features softhsm2 -- tests::test_hsm_softhsm2_all
//! ```
use std::{collections::HashMap, ptr};

use cosmian_kms_base_hsm::{
    HResult, RsaOaepDigest,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};
use libloading::Library;
use pkcs11_sys::{CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR, CKF_OS_LOCKING_OK, CKR_OK};

use crate::{SOFTHSM2_PKCS11_LIB, SofthsmCapabilityProvider};

const SLOT_ID: usize = 0x01; // SoftHSM2 fallback slot if HSM_SLOT_ID is not set

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("SOFTHSM2_PKCS11_LIB", SOFTHSM2_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA1),
        threads: 4,
        supports_rsa_wrap: true,
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
    test_hsm_softhsm2_get_info()?;
    test_hsm_softhsm2_get_mechanisms()?;
    test_hsm_softhsm2_get_supported_algorithms()?;
    test_hsm_softhsm2_destroy_all()?;
    test_hsm_softhsm2_generate_aes_key()?;
    test_hsm_softhsm2_generate_rsa_keypair()?;
    test_hsm_softhsm2_rsa_key_wrap()?;
    test_hsm_softhsm2_rsa_pkcs_encrypt()?;
    test_hsm_softhsm2_rsa_oaep_encrypt()?;
    test_hsm_softhsm2_aes_gcm_encrypt()?;
    test_hsm_softhsm2_aes_cbc_encrypt()?;
    test_hsm_softhsm2_aes_cbc_multi_round_encrypt()?;
    test_hsm_softhsm2_multi_threaded_rsa_encrypt_decrypt_test()?;
    test_hsm_softhsm2_get_key_metadata()?;
    test_hsm_softhsm2_list_objects()?;
    test_hsm_softhsm2_search_incompatible_key()?;
    test_hsm_softhsm2_destroy_all()?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_low_level_test() -> HResult<()> {
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
    let rv = init(&raw mut p_init_args as CK_VOID_PTR);
    assert_eq!(rv, CKR_OK);

    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_info() -> HResult<()> {
    shared::get_info::<SofthsmCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_mechanisms() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::get_mechanisms_and_hashes(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_supported_algorithms() -> HResult<()> {
    shared::get_supported_algorithms::<SofthsmCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_generate_aes_key() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::generate_aes_key(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_generate_rsa_keypair() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::generate_rsa_keypair(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_key_wrap() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA1)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_pkcs_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_pkcs_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_oaep_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA1)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_gcm_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::aes_gcm_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_cbc_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::aes_cbc_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_cbc_multi_round_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::aes_cbc_multi_round(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA1, 4)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_list_objects() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::list_objects(&slot)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_key_metadata() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<SofthsmCapabilityProvider>(&cfg()?)?;
    shared::get_key_metadata(&slot)
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

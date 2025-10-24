//! These tests require a connection to a working HSM and are gated behind the `crypt2pay` feature.
//! To run a test, cd into this crate directory and run (replace `XXX` with the actual password):
//!
//! ```bash
//! HSM_USER_PASSWORD=XXX cargo test --release --target x86_64-unknown-linux-gnu --features crypt2pay -- tests::test_hsm_crypt2pay_all
//! ```

use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    test_helpers::get_hsm_password, tests_shared as shared, HResult, RsaOaepDigest,
};

use crate::{Crypt2payCapabilityProvider, CRYPT2PAY_PKCS11_LIB};

const LIB_PATH: &str = CRYPT2PAY_PKCS11_LIB;
const SLOT_ID: usize = 0x04; // Crypt2pay default slot

fn cfg() -> HResult<shared::HsmTestConfig<'static>> {
    let user_password = get_hsm_password()?;
    Ok(shared::HsmTestConfig {
        lib_path: LIB_PATH,
        slot_ids_and_passwords: HashMap::from([(SLOT_ID, Some(user_password))]),
        slot_id_for_tests: SLOT_ID,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA256),
        threads: 4,
        supports_rsa_wrap: true,
    })
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_all() -> HResult<()> {
    test_hsm_crypt2pay_get_info()?;
    test_hsm_crypt2pay_get_mechanisms()?;
    test_hsm_crypt2pay_get_supported_algorithms()?;
    test_hsm_crypt2pay_destroy_all()?;
    test_hsm_crypt2pay_generate_aes_key()?;
    test_hsm_crypt2pay_generate_rsa_keypair()?;
    test_hsm_crypt2pay_rsa_key_wrap()?;
    test_hsm_crypt2pay_rsa_pkcs_encrypt()?;
    test_hsm_crypt2pay_rsa_oaep_encrypt()?;
    test_hsm_crypt2pay_aes_gcm_encrypt()?;
    test_hsm_crypt2pay_multi_threaded_rsa_encrypt_decrypt_test()?;
    test_hsm_crypt2pay_get_key_metadata()?;
    test_hsm_crypt2pay_list_objects()?;
    test_hsm_crypt2pay_search_incompatible_key()?;
    test_hsm_crypt2pay_destroy_all()?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_get_info() -> HResult<()> {
    shared::get_info::<Crypt2payCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_get_mechanisms() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::get_mechanisms_and_hashes(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_get_supported_algorithms() -> HResult<()> {
    shared::get_supported_algorithms::<Crypt2payCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_generate_aes_key() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::generate_aes_key(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_generate_rsa_keypair() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::generate_rsa_keypair(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_rsa_key_wrap() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA256)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_rsa_pkcs_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::rsa_pkcs_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_rsa_oaep_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA256)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_aes_gcm_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::aes_gcm_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA256, 4)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_list_objects() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::list_objects(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_get_key_metadata() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::get_key_metadata(&slot)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_search_incompatible_key() -> HResult<()> {
    let config = &cfg()?;
    let hsm = shared::instantiate::<Crypt2payCapabilityProvider>(config)?;
    shared::search_incompatible_key(&hsm, &cfg()?)
}

#[test]
#[ignore = "Requires Linux, Crypt2pay PKCS#11 library, and HSM environment"]
fn test_hsm_crypt2pay_destroy_all() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<Crypt2payCapabilityProvider>(&cfg()?)?;
    shared::destroy_all(&slot)
}

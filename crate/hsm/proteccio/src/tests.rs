//! These tests require a connection to a working HSM and are gated behind the `proteccio` feature.
//! To run a test, cd into this crate directory and run (replace `XXX` with the actual password):
//!
//! ```bash
//! HSM_USER_PASSWORD=XXX cargo test --release --target x86_64-unknown-linux-gnu --features proteccio -- tests::test_hsm_proteccio_all
//! ```

use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    HResult, RsaOaepDigest,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{PROTECCIO_PKCS11_LIB, ProteccioCapabilityProvider};

const SLOT_ID: usize = 0x01; // Proteccio default slot

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("PROTECCIO_PKCS11_LIB", PROTECCIO_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA256),
        threads: 4,
        supports_rsa_wrap: true,
    })
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_all() -> HResult<()> {
    test_hsm_proteccio_get_info()?;
    test_hsm_proteccio_get_mechanisms()?;
    test_hsm_proteccio_get_supported_algorithms()?;
    test_hsm_proteccio_destroy_all()?;
    test_hsm_proteccio_generate_aes_key()?;
    test_hsm_proteccio_generate_rsa_keypair()?;
    test_hsm_proteccio_rsa_key_wrap()?;
    test_hsm_proteccio_rsa_pkcs_encrypt()?;
    test_hsm_proteccio_rsa_oaep_encrypt()?;
    test_hsm_proteccio_aes_gcm_encrypt()?;
    test_hsm_proteccio_multi_threaded_rsa_encrypt_decrypt_test()?;
    test_hsm_proteccio_get_key_metadata()?;
    test_hsm_proteccio_list_objects()?;
    test_hsm_proteccio_search_incompatible_key()?;
    test_hsm_proteccio_destroy_all()?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_get_info() -> HResult<()> {
    shared::get_info::<ProteccioCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_get_mechanisms() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::get_mechanisms_and_hashes(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_get_supported_algorithms() -> HResult<()> {
    shared::get_supported_algorithms::<ProteccioCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_generate_aes_key() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::generate_aes_key(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_generate_rsa_keypair() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::generate_rsa_keypair(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_rsa_key_wrap() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA256)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_rsa_pkcs_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::rsa_pkcs_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_rsa_oaep_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA256)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_aes_gcm_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::aes_gcm_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA256, 4)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_list_objects() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::list_objects(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_get_key_metadata() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::get_key_metadata(&slot)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_search_incompatible_key() -> HResult<()> {
    let config = &cfg()?;
    let hsm = shared::instantiate::<ProteccioCapabilityProvider>(config)?;
    shared::search_incompatible_key(&hsm, &cfg()?)
}

#[test]
#[ignore = "Requires Linux, Proteccio PKCS#11 library, and HSM environment"]
fn test_hsm_proteccio_destroy_all() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<ProteccioCapabilityProvider>(&cfg()?)?;
    shared::destroy_all(&slot)
}

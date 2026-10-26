//! These tests require a Thales Luna Client and a Luna HSM partition, and are gated behind the
//! `luna` feature. Run them with (replace `XXX` with the partition password):
//!
//! ```bash
//! HSM_USER_PASSWORD=XXX HSM_SLOT_ID=0 cargo test -p luna_pkcs11_loader --features luna,non-fips \
//!   -- --ignored tests::test_hsm_luna_all
//! ```
//!
//! Luna test partitions are shared: unlike the other vendor suites, these tests never call
//! `shared::destroy_all`. Each test snapshots the slot first and, even when it fails or panics,
//! destroys only the new objects whose `CKA_ID` carries the shared tests' `kms-test-` prefix:
//! objects other users create on the partition meanwhile are left alone.

use std::{collections::HashMap, sync::Arc};

use cosmian_kms_base_hsm::{
    HResult, RsaOaepDigest, SlotManager,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{LUNA_PKCS11_LIB, LunaCapabilityProvider};

const SLOT_ID: usize = 0;

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("LUNA_PKCS11_LIB", LUNA_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        threads: 4,
    })
}

/// Run `test`, then destroy only the objects it created on `slot`, even when it panics.
fn with_cleanup(slot: &Arc<SlotManager>, test: impl FnOnce() -> HResult<()>) -> HResult<()> {
    let before = shared::object_handles(slot)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
    shared::destroy_created_since(slot, &before)?;
    outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Run `test` on the test slot, then destroy only the objects it created.
fn scoped(test: impl FnOnce(&Arc<SlotManager>) -> HResult<()>) -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<LunaCapabilityProvider>(&cfg()?)?;
    with_cleanup(&slot, || test(&slot))
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_all() -> HResult<()> {
    let cfg = cfg()?;
    let hsm = shared::instantiate::<LunaCapabilityProvider>(&cfg)?;
    drop(hsm.hsm_lib().get_info_struct()?);
    let slot = shared::get_slot::<LunaCapabilityProvider>(&hsm, &cfg)?;
    with_cleanup(&slot, || {
        shared::get_mechanisms_and_hashes(&slot)?;
        drop(hsm.get_algorithms(cfg.slot_id_for_tests)?);
        shared::generate_aes_key(&slot)?;
        shared::generate_rsa_keypair(&slot)?;
        shared::generate_ec_keypair(&slot)?;
        shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA256)?;
        shared::rsa_pkcs_encrypt(&slot)?;
        shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA256)?;
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
        shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA256, cfg.threads)?;
        shared::concurrent_sign_does_not_degrade(&slot)?;
        shared::get_key_metadata(&slot, true)?;
        shared::list_objects(&slot)?;
        shared::search_incompatible_key(&hsm, &cfg)
    })
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_get_info() -> HResult<()> {
    shared::get_info::<LunaCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_get_mechanisms() -> HResult<()> {
    scoped(shared::get_mechanisms_and_hashes)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_get_supported_algorithms() -> HResult<()> {
    shared::get_supported_algorithms::<LunaCapabilityProvider>(&cfg()?)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_generate_aes_key() -> HResult<()> {
    scoped(shared::generate_aes_key)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_generate_rsa_keypair() -> HResult<()> {
    scoped(shared::generate_rsa_keypair)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_generate_ec_keypair() -> HResult<()> {
    scoped(shared::generate_ec_keypair)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_key_wrap() -> HResult<()> {
    scoped(|slot| shared::rsa_key_wrap(slot, RsaOaepDigest::SHA256))
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_pkcs_encrypt() -> HResult<()> {
    scoped(shared::rsa_pkcs_encrypt)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_oaep_encrypt() -> HResult<()> {
    scoped(|slot| shared::rsa_oaep_encrypt(slot, RsaOaepDigest::SHA256))
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_aes_gcm_encrypt() -> HResult<()> {
    scoped(shared::aes_gcm_encrypt)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_aes_cbc_encrypt() -> HResult<()> {
    scoped(shared::aes_cbc_encrypt)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_aes_cbc_multi_round_encrypt() -> HResult<()> {
    scoped(shared::aes_cbc_multi_round)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_pkcs_v15_sign() -> HResult<()> {
    scoped(shared::rsa_pkcs_v15_sign)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_sha256_sign() -> HResult<()> {
    scoped(shared::rsa_sha256_sign)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_sign_all_algorithms() -> HResult<()> {
    scoped(shared::rsa_sign_all_algorithms)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_rsa_pss_sign_all_algorithms() -> HResult<()> {
    scoped(shared::rsa_pss_sign_all_algorithms)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_ecdsa_sign_all_curves_and_hashes() -> HResult<()> {
    scoped(shared::ecdsa_sign_all_curves_and_hashes)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    scoped(|slot| shared::multi_threaded_rsa(slot, RsaOaepDigest::SHA256, 4))
}

#[cfg(feature = "non-fips")]
#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_eddsa_sign_all_curves() -> HResult<()> {
    scoped(shared::eddsa_sign_all_curves)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_concurrent_sign_does_not_degrade() -> HResult<()> {
    scoped(shared::concurrent_sign_does_not_degrade)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_list_objects() -> HResult<()> {
    scoped(shared::list_objects)
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_get_key_metadata() -> HResult<()> {
    scoped(|slot| shared::get_key_metadata(slot, true))
}

#[test]
#[ignore = "Requires Linux, the Thales Luna Client and a Luna HSM partition"]
fn test_hsm_luna_search_incompatible_key() -> HResult<()> {
    let cfg = cfg()?;
    let hsm = shared::instantiate::<LunaCapabilityProvider>(&cfg)?;
    let slot = shared::get_slot::<LunaCapabilityProvider>(&hsm, &cfg)?;
    let before = shared::object_handles(&slot)?;
    let result = shared::search_incompatible_key(&hsm, &cfg);
    shared::destroy_created_since(&slot, &before)?;
    result
}

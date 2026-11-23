//! These tests require the Idemia SPHERE HSM or the Windows Idemia HSM simulator and are gated
//! behind the `idemia_sphere` feature. Stage the simulator with
//! `.github/reusable_scripts/prepare_idemia_hsm.ps1`, then (replace the slot id):
//! ```
//! HSM_USER_PASSWORD=12345678 HSM_SLOT_ID=962602111 cargo test -p idemia_sphere_pkcs11_loader --features idemia_sphere -- --ignored tests::test_hsm_idemia_sphere_all
//! ```
use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    HResult,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{IDEMIA_SPHERE_PKCS11_LIB, IdemiaSphereCapabilityProvider};

fn cfg() -> HResult<shared::HsmTestConfig> {
    let user_password = get_hsm_password()?;
    // No fallback slot: the slot ids are derived from the token serial numbers.
    let slot = get_hsm_slot_id()?;
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("IDEMIA_SPHERE_PKCS11_LIB", IDEMIA_SPHERE_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        threads: 4,
    })
}

/// Runs a step that exercises a mechanism a `SECURITY_LEVEL=FIPS` simulator rejects at use (e.g.
/// raw `CKM_RSA_PKCS`) although it lists it. With the `non-fips` feature the simulator runs its
/// non-FIPS profile and the step must pass.
#[cfg(feature = "non-fips")]
fn non_fips_only_step(_name: &str, result: HResult<()>) -> HResult<()> {
    result
}

/// See the `non-fips` variant.
#[cfg(not(feature = "non-fips"))]
fn non_fips_only_step(name: &str, result: HResult<()>) -> HResult<()> {
    shared::skip_when_mechanism_refused(name, result)
}

/// AES key wrap is mandatory with the `non-fips` feature (the simulator then runs its non-FIPS
/// profile). Without it, a `SECURITY_LEVEL=FIPS` simulator offers no AES-KW/KWP, so the step is
/// skipped when the slot's mechanism list does not offer them.
#[cfg(feature = "non-fips")]
fn aes_key_wrap_step(
    slot: &std::sync::Arc<cosmian_kms_base_hsm::SlotManager>,
    slot_id: usize,
) -> HResult<()> {
    shared::aes_key_wrap(slot, slot_id)
}

/// See the `non-fips` variant.
#[cfg(not(feature = "non-fips"))]
fn aes_key_wrap_step(
    slot: &std::sync::Arc<cosmian_kms_base_hsm::SlotManager>,
    slot_id: usize,
) -> HResult<()> {
    shared::aes_key_wrap_if_offered(slot, slot_id)
}

/// To run all the tests, try something like
/// ```sh
///  RUST_LOG=info \
///  HSM_USER_PASSWORD="12345678" \
///  HSM_SLOT_ID=962602111 \
///  cargo test test_hsm_idemia_sphere_all --features idemia_sphere -- --ignored
/// ```
/// WARNING: Initialized tokens are reassigned to another slot (based on the token serial number)
/// So show the available slots first to determine which slot ID to use
#[test]
#[ignore = "Requires the Idemia SPHERE HSM or the Windows Idemia HSM simulator"]
fn test_hsm_idemia_sphere_all() -> HResult<()> {
    // Use a single BaseHsm for the entire test to prevent repeated C_Initialize/C_Finalize
    // cycles.
    let cfg = cfg()?;
    let hsm = shared::instantiate::<IdemiaSphereCapabilityProvider>(&cfg)?;
    shared::get_info(&hsm)?;
    let slot = shared::get_slot::<IdemiaSphereCapabilityProvider>(&hsm, &cfg)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    shared::get_supported_algorithms(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, shared::TEST_RSA_OAEP_DIGEST)?;
    shared::rsa_pkcs_encrypt(&slot)?;
    shared::aes_gcm_encrypt_token_without_iv_generation(&slot)?;
    aes_key_wrap_step(&slot, cfg.slot_id_for_tests)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::aes_cbc_multi_round(&slot)?;
    shared::aes_cbc_multi_part(&slot)?;
    shared::aes_mac_known_answers(&slot)?;
    shared::aes_gcm_known_answers(&slot)?;
    non_fips_only_step("rsa_pkcs_v15_sign", shared::rsa_pkcs_v15_sign(&slot))?;
    shared::rsa_sha256_sign(&slot)?;
    shared::rsa_sign_all_algorithms(&slot)?;
    shared::rsa_pss_sign_all_algorithms(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    #[cfg(feature = "non-fips")]
    shared::eddsa_sign_all_curves(&slot)?;
    shared::concurrent_sign_does_not_degrade(&slot)?;
    shared::get_key_metadata(&slot)?;
    shared::list_objects(&slot)?;
    shared::search_incompatible_key(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    Ok(())
}

#[test]
#[ignore = "Requires the Idemia SPHERE HSM or the Windows Idemia HSM simulator"]
fn test_hsm_idemia_sphere_low_level_test() -> HResult<()> {
    shared::low_level_init_test(&cfg()?)
}

/// Additive PKCS#11 v3 capability probe (issue #1153).
///
/// The probe must preserve ordinary PKCS#11 operation and consistently report either no v3
/// discovery symbol (the Idemia simulator exports only the classic `C_*` functions) or the
/// interfaces returned by that symbol.
#[test]
#[ignore = "Requires the Idemia SPHERE HSM or the Windows Idemia HSM simulator"]
fn test_hsm_idemia_sphere_pkcs11_v3_capability_probe_is_additive() -> HResult<()> {
    let cfg = cfg()?;
    let hsm = shared::instantiate::<IdemiaSphereCapabilityProvider>(&cfg)?;

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

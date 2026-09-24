//! Live tests for Google's `libkmsp11.so` compatibility library.

use std::collections::HashMap;

use cosmian_kms_base_hsm::{HError, HResult, tests_shared as shared};

use crate::{GCP_CLOUD_HSM_PKCS11_LIB, GcpCloudHsmCapabilityProvider};

fn cfg() -> HResult<shared::HsmTestConfig> {
    let slot = std::env::var("HSM_SLOT_ID")
        .ok()
        .map(|value| {
            value
                .parse()
                .map_err(|error| HError::Default(format!("Invalid HSM_SLOT_ID: {error}")))
        })
        .transpose()?
        .unwrap_or(0);
    let password = std::env::var("HSM_USER_PASSWORD")
        .map_err(|error| HError::Default(format!("HSM_USER_PASSWORD is not set: {error}")))?;
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("GCP_CLOUD_HSM_PKCS11_LIB", GCP_CLOUD_HSM_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(password))]),
        slot_id_for_tests: slot,
        rsa_oaep_digest: None,
        threads: 4,
        supports_rsa_wrap: false,
    })
}

#[test]
#[ignore = "Requires Linux, Google's libkmsp11.so, Cloud KMS configuration, and a live HSM-tier key ring"]
fn test_hsm_gcp_cloud_hsm_all() -> HResult<()> {
    let config = cfg()?;
    let hsm = shared::instantiate::<GcpCloudHsmCapabilityProvider>(&config)?;
    drop(hsm.hsm_lib().get_info_struct()?);
    let slot = shared::get_slot::<GcpCloudHsmCapabilityProvider>(&hsm, &config)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    drop(hsm.get_algorithms(config.slot_id_for_tests)?);
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::aes_gcm_encrypt(&slot)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    shared::get_key_metadata(&slot)?;
    shared::list_objects(&slot)?;
    shared::destroy_all(&slot)
}

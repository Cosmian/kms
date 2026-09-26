//! Live tests for a Thales Luna 7 HSM used through Azure Dedicated HSM.

use std::collections::HashMap;

use cosmian_kms_base_hsm::{HResult, RsaOaepDigest, tests_shared as shared};

use crate::{AZURE_DEDICATED_HSM_PKCS11_LIB, AzureDedicatedHsmCapabilityProvider};

fn cfg() -> HResult<shared::HsmTestConfig> {
    let slot = cosmian_kms_base_hsm::test_helpers::get_hsm_slot_id().unwrap_or(0);
    let password = cosmian_kms_base_hsm::test_helpers::get_hsm_password()?;
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path(
            "AZURE_DEDICATED_HSM_PKCS11_LIB",
            AZURE_DEDICATED_HSM_PKCS11_LIB,
        ),
        slot_ids_and_passwords: HashMap::from([(slot, Some(password))]),
        slot_id_for_tests: slot,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA256),
        threads: 4,
        supports_rsa_wrap: true,
    })
}

#[test]
#[ignore = "Requires Linux, the Thales Luna 7 PKCS#11 library, and a live Azure Dedicated HSM"]
fn test_hsm_azure_dedicated_hsm_all() -> HResult<()> {
    let config = cfg()?;
    let hsm = shared::instantiate::<AzureDedicatedHsmCapabilityProvider>(&config)?;
    drop(hsm.hsm_lib().get_info_struct()?);
    let slot = shared::get_slot::<AzureDedicatedHsmCapabilityProvider>(&hsm, &config)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    drop(hsm.get_algorithms(config.slot_id_for_tests)?);
    shared::destroy_all(&slot)?;
    shared::generate_aes_key_with_exportability(&slot, false)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA256)?;
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA256)?;
    shared::aes_gcm_encrypt(&slot)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    shared::get_key_metadata(&slot, false)?;
    shared::list_objects(&slot)?;
    shared::destroy_all(&slot)
}

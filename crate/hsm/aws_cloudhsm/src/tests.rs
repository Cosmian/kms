//! These tests require a connection to a live AWS `CloudHSM` cluster and are gated behind the
//! `aws_cloudhsm` feature.
//! To run a test, cd into the crate directory and run (replace values with your CU credentials):
//! ```bash
//! AWS_CLOUDHSM_PKCS11_LIB=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
//!   HSM_USER_PASSWORD="cu_username:cu_password" \
//!   cargo test --target x86_64-unknown-linux-gnu --features aws_cloudhsm -- tests::test_hsm_aws_cloudhsm_all --ignored --exact
//! ```
//! See the crate `README.md` for the one-time cluster/CU provisioning runbook and the
//! `configure-pkcs11 add-cluster` setup step that must be run before these tests can connect.

use std::collections::HashMap;

use cosmian_kms_base_hsm::{
    HResult, RsaOaepDigest,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

use crate::{AWS_CLOUDHSM_PKCS11_LIB, AwsCloudHsmCapabilityProvider};

const SLOT_ID: usize = 0x00; // First slot registered by `configure-pkcs11 add-cluster`

fn cfg() -> HResult<shared::HsmTestConfig> {
    // The AWS CloudHSM CU login PIN is "<cu_username>:<cu_password>" - see lib.rs doc comment.
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id().unwrap_or(SLOT_ID);
    Ok(shared::HsmTestConfig {
        lib_path: shared::lib_path("AWS_CLOUDHSM_PKCS11_LIB", AWS_CLOUDHSM_PKCS11_LIB),
        slot_ids_and_passwords: HashMap::from([(slot, Some(user_password))]),
        slot_id_for_tests: slot,
        threads: 4,
    })
}

#[test]
#[ignore = "Requires Linux, the AWS CloudHSM PKCS#11 library, and a live cluster"]
fn test_hsm_aws_cloudhsm_all() -> HResult<()> {
    // Use a single BaseHsm for the entire test to prevent repeated C_Initialize/C_Finalize
    // cycles. Some PKCS#11 native libraries are not safely re-initializable within the same
    // process: repeated load/unload cycles can corrupt internal C state and cause a SIGSEGV.
    let cfg = cfg()?;
    let hsm = shared::instantiate::<AwsCloudHsmCapabilityProvider>(&cfg)?;
    shared::get_info(&hsm)?;
    let slot = shared::get_slot::<AwsCloudHsmCapabilityProvider>(&hsm, &cfg)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    shared::get_supported_algorithms(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::generate_ec_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA256)?;
    // `rsa_pkcs_encrypt` is intentionally standalone-only: AWS CloudHSM Client SDK 5 may
    // restrict RSA PKCS#1 v1.5 encrypt/decrypt on FIPS-mode clusters (unverified here), so it
    // is not folded into the CI-run aggregator until confirmed against a live cluster.
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
    shared::get_key_metadata(&slot)?;
    shared::list_objects(&slot)?;
    shared::search_incompatible_key(&hsm, &cfg)?;
    shared::destroy_all(&slot)?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, the AWS CloudHSM PKCS#11 library, and a live cluster"]
fn test_hsm_aws_cloudhsm_rsa_pkcs_encrypt() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<AwsCloudHsmCapabilityProvider>(&cfg()?)?;
    shared::rsa_pkcs_encrypt(&slot)
}

#[test]
#[ignore = "Requires Linux, the AWS CloudHSM PKCS#11 library, and a live cluster"]
fn test_hsm_aws_cloudhsm_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<AwsCloudHsmCapabilityProvider>(&cfg()?)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA256, 4)
}

#[test]
#[ignore = "Requires Linux, the AWS CloudHSM PKCS#11 library, and a live cluster"]
fn test_hsm_aws_cloudhsm_search_incompatible_key() -> HResult<()> {
    let config = &cfg()?;
    let hsm = shared::instantiate::<AwsCloudHsmCapabilityProvider>(config)?;
    shared::search_incompatible_key(&hsm, &cfg()?)
}

#[test]
#[ignore = "Requires Linux, the AWS CloudHSM PKCS#11 library, and a live cluster"]
fn test_hsm_aws_cloudhsm_destroy_all() -> HResult<()> {
    let slot = shared::instantiate_and_get_slot::<AwsCloudHsmCapabilityProvider>(&cfg()?)?;
    shared::destroy_all(&slot)
}

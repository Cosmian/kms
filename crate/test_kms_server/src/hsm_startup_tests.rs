//! Ignored end-to-end startup checks for test:hsm backend tasks.

use std::env;

#[cfg(not(feature = "non-fips"))]
use crate::start_default_test_kms_server_with_hsm_and_kek_for_vectors;
use crate::{
    start_default_test_kms_server_with_hsm_and_kek,
    start_default_test_kms_server_with_utimaco_and_kek,
};

#[cfg(not(feature = "non-fips"))]
fn assert_fips_startup_result<E: std::fmt::Display>(
    result: Result<crate::TestsContext, E>,
    simulator: bool,
) {
    match (result, simulator) {
        (Ok(_), true) => {
            panic!("Crypt2Pay simulator unexpectedly started with an AES-GCM KEK in FIPS")
        }
        (Err(error), true) => assert!(
            error
                .to_string()
                .contains("AES-GCM encryption needs an IV generated inside the HSM"),
            "unexpected FIPS simulator startup error: {error}"
        ),
        (Ok(context), false) => assert!(context.server_port > 0),
        (Err(error), false) => assert!(
            error
                .to_string()
                .contains("AES-GCM encryption needs an IV generated inside the HSM"),
            "unexpected FIPS HSM startup error: {error}"
        ),
    }
}

fn require_hsm_env(expected_model: &str) {
    assert_eq!(env::var("HSM_MODEL").ok().as_deref(), Some(expected_model));
    assert!(env::var_os("HSM_SLOT_ID").is_some());
    assert!(env::var_os("HSM_USER_PASSWORD").is_some());
}
async fn test_hsm_kek_startup(expected_model: &str) {
    require_hsm_env(expected_model);
    let context = start_default_test_kms_server_with_hsm_and_kek().await;
    assert!(
        context.server_port > 0,
        "KMS server must start with the HSM KEK configuration"
    );
}

#[tokio::test]
#[ignore = "Requires Utimaco — invoked by mise run test:hsm:utimaco"]
async fn test_startup_with_hsm_kek_utimaco() {
    let context = start_default_test_kms_server_with_utimaco_and_kek().await;
    assert!(
        context.server_port > 0,
        "KMS server must start with the Utimaco HSM KEK configuration"
    );
}

#[tokio::test]
#[ignore = "Requires SoftHSM2 — invoked by mise run test:hsm-softhsm2"]
async fn test_startup_with_hsm_kek_softhsm2() {
    test_hsm_kek_startup("softhsm2").await;
}

#[tokio::test]
#[ignore = "Requires Kryoptic — invoked by mise run test:hsm-kryoptic"]
async fn test_startup_with_hsm_kek_kryoptic() {
    test_hsm_kek_startup("kryoptic").await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires Proteccio — invoked by mise run test:hsm-proteccio"]
async fn test_startup_with_hsm_kek_proteccio() {
    test_hsm_kek_startup("proteccio").await;
}

#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires Proteccio — invoked by mise run test:hsm-proteccio"]
async fn test_startup_with_hsm_kek_proteccio() {
    require_hsm_env("proteccio");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert_fips_startup_result(result, false);
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires Crypt2Pay — invoked by mise run test:hsm:crypt2pay"]
async fn test_startup_with_hsm_kek_crypt2pay() {
    test_hsm_kek_startup("crypt2pay").await;
}

#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires Crypt2Pay — invoked by mise run test:hsm:crypt2pay"]
async fn test_startup_with_hsm_kek_crypt2pay() {
    require_hsm_env("crypt2pay");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert_fips_startup_result(result, false);
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires Crypt2Pay simulator — invoked by mise run test:hsm:crypt2pay-simulator"]
async fn test_startup_with_hsm_kek_crypt2pay_simulator() {
    test_hsm_kek_startup("crypt2pay").await;
}

#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires Crypt2Pay simulator — invoked by mise run test:hsm:crypt2pay-simulator"]
async fn test_startup_with_hsm_kek_crypt2pay_simulator() {
    require_hsm_env("crypt2pay");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert_fips_startup_result(result, true);
}

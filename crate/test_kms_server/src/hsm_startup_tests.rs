//! Ignored end-to-end startup checks for test:hsm backend tasks.

use std::env;

use crate::start_default_test_kms_server_with_hsm_and_kek_for_vectors;
use crate::{
    start_default_test_kms_server_with_hsm_and_kek,
    start_default_test_kms_server_with_utimaco_and_kek,
};
use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN, kmip_operations::Get,
        kmip_types::CryptographicAlgorithm, requests::symmetric_key_create_request,
    },
};

#[cfg(not(feature = "non-fips"))]
fn assert_fips_startup_result<E: std::fmt::Display>(
    result: Result<crate::TestsContext, E>,
    simulator: bool,
) {
    if simulator {
        assert!(
            result.is_err(),
            "{} unexpectedly started with an AES-GCM KEK in FIPS",
            env::var("HSM_MODEL").unwrap_or_default()
        );
    }

    match result {
        Ok(context) => assert!(context.server_port > 0),
        Err(error) => assert!(
            error
                .to_string()
                .contains("AES-GCM encryption needs an IV generated inside the HSM"),
            "unexpected FIPS {} startup error: {error}",
            if simulator { "simulator" } else { "HSM" }
        ),
    }
}

fn require_hsm_env(expected_model: &str) {
    assert_eq!(env::var("HSM_MODEL").ok().as_deref(), Some(expected_model));
    assert!(env::var_os("HSM_SLOT_ID").is_some());
    assert!(env::var_os("HSM_USER_PASSWORD").is_some());
}
async fn test_hsm_kek_startup(expected_model: &str) {
    crate::init_test_logging();
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
    crate::init_test_logging();
    let context = start_default_test_kms_server_with_utimaco_and_kek().await;
    assert!(
        context.server_port > 0,
        "KMS server must start with the Utimaco HSM KEK configuration"
    );
}

#[tokio::test]
#[ignore = "Requires SoftHSM2 — invoked by mise run test:hsm:softhsm2"]
async fn test_startup_with_hsm_kek_softhsm2() {
    test_hsm_kek_startup("softhsm2").await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires the Idemia HSM simulator — invoked by mise run test:hsm:idemia-sphere-simulator"]
async fn test_startup_with_hsm_kek_idemia_sphere_simulator() {
    test_hsm_kek_startup("idemia_sphere").await;
}

#[tokio::test]
#[ignore = "Requires Kryoptic — invoked by mise run test:hsm:kryoptic"]
async fn test_startup_with_hsm_kek_kryoptic() {
    test_hsm_kek_startup("kryoptic").await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires Proteccio — invoked by mise run test:hsm:proteccio"]
async fn test_startup_with_hsm_kek_proteccio() {
    test_hsm_kek_startup("proteccio").await;
}

#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires Proteccio — invoked by mise run test:hsm:proteccio"]
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

/// `hsm_model = "other"` with a library that refuses caller AES-GCM IVs: the KMS must boot
/// with an HSM-backed KEK by letting the module generate the IV itself.
#[tokio::test]
#[ignore = "Requires a PKCS#11 library refusing caller GCM IVs — invoked by mise run test:hsm:other"]
async fn test_startup_with_hsm_kek_other() {
    test_hsm_kek_startup("other").await;
}

/// A user key created on a server whose storage KEK sits in the HSM and wraps with AES-GCM
/// (never `aes-key-wrap-padding`) is wrapped by the HSM at rest and unwrapped by it on `Get`:
/// the key bytes must come back with the requested length and be fresh.
///
/// Run it against `hsm_model = "other"` fronted by the IV shim (`HSM_MODEL=other`): in a FIPS
/// build the shim only accepts an all-zero IV buffer and generates the IV itself, so this proves
/// the whole wrap/unwrap path works with HSM-generated IVs. The task driving it checks the shim
/// marker afterwards (every GCM init had a zero IV, none a caller IV).
#[tokio::test]
#[ignore = "Requires a PKCS#11 library fronted by the IV shim — invoked by test_hsm_other/test_hsm_idemia"]
async fn test_hsm_kek_gcm_user_key_round_trip_other() -> Result<(), Box<dyn std::error::Error>> {
    crate::init_test_logging();
    require_hsm_env("other");
    let context = start_default_test_kms_server_with_hsm_and_kek().await;
    let client = context.get_owner_client();
    let created = client
        .create(symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            ["hsm_kek_gcm_round_trip"],
            false,
            None,
        )?)
        .await?;
    // Stored as registered, the key is wrapped by the HSM-held KEK.
    let as_stored = client
        .get(Get::from(&created.unique_identifier))
        .await?
        .object;
    if as_stored.key_block()?.key_wrapping_data.is_none() {
        return Err("the user key must be wrapped by the KEK at rest".into());
    }
    // Asking for it unwrapped makes the server unwrap it with the HSM (AES-GCM decryption), twice.
    let unwrapped_request = || Get {
        unique_identifier: Some(created.unique_identifier.clone()),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        ..Get::default()
    };
    let first = client
        .get(unwrapped_request())
        .await?
        .object
        .key_block()?
        .key_bytes()?;
    if first.len() != 32 {
        return Err(format!("unexpected unwrapped key length {}", first.len()).into());
    }
    if first.iter().all(|byte| *byte == 0) {
        return Err("the unwrapped key must not be all zeros".into());
    }
    let second = client
        .get(unwrapped_request())
        .await?
        .object
        .key_block()?
        .key_bytes()?;
    if first != second {
        return Err("the unwrap path must return the same key bytes twice".into());
    }
    Ok(())
}

/// FIPS build, HSM that cannot generate an AES-GCM IV (plain `SoftHSM2` as `hsm_model = "other"`,
/// no shim): the AES-GCM KEK is refused at startup and nothing is stored.
#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires a PKCS#11 library that does not generate GCM IVs — invoked by test_hsm_other"]
async fn test_startup_with_hsm_kek_other_without_iv_generation() {
    crate::init_test_logging();
    require_hsm_env("other");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert_fips_startup_result(result, true);
}

/// FIPS build on the Idemia simulator in `SECURITY_LEVEL=FIPS`: it forwards `CKM_AES_GCM`
/// without generating an IV, so the AES-GCM KEK is refused at startup.
#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires the Idemia HSM simulator — invoked by test_hsm_idemia.ps1"]
async fn test_startup_with_hsm_kek_idemia_sphere_simulator() {
    crate::init_test_logging();
    require_hsm_env("idemia_sphere");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert_fips_startup_result(result, true);
}

/// FIPS build on the Idemia simulator (`SECURITY_LEVEL=FIPS`) behind the IV shim, which plays the
/// module that generates the AES-GCM IV: the AES-GCM KEK boots and the IV is HSM-generated.
#[cfg(not(feature = "non-fips"))]
#[tokio::test]
#[ignore = "Requires the Idemia HSM simulator behind the IV shim — invoked by test_hsm_idemia.ps1"]
async fn test_startup_with_hsm_kek_idemia_sphere_simulator_iv_layer() {
    test_hsm_kek_startup("idemia_sphere").await;
}

/// Non-FIPS build, `hsm_model = "other"` module that generates its own AES-GCM IVs and refuses the
/// KMS-chosen one (the IV shim without `ACCEPT_CALLER_IV`): `other` assumes a module that accepts a
/// caller IV outside FIPS, so the AES-GCM KEK is refused at startup, with the advice to pick a
/// wrapping algorithm that needs no IV, instead of silently running with a broken KEK.
#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires a PKCS#11 library refusing caller GCM IVs — invoked by test_hsm_other"]
async fn test_startup_with_hsm_kek_other_refusing_caller_iv() {
    crate::init_test_logging();
    require_hsm_env("other");
    let result = start_default_test_kms_server_with_hsm_and_kek_for_vectors().await;
    assert!(
        result.is_err(),
        "the KEK must be refused when the module rejects the KMS-chosen IV"
    );
    let message = result
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("AES-GCM wrapping failed on this HSM")
            && message.contains("aes-key-wrap-padding"),
        "unexpected startup error: {message}"
    );
}

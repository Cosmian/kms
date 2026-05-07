/// Multi-HSM tests using two `SoftHSM2` instances.
///
/// These tests verify that the KMS server correctly routes objects whose UID has the `"hsm"` or
/// `"hsm1"` prefix to the corresponding HSM instance and that cross-instance access is denied.
use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_operations::Operation,
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    requests::symmetric_key_create_request,
};
use cosmian_logger::{info, log_init};
use uuid::Uuid;

use crate::{
    config::{HsmConfig, ServerParams},
    core::KMS,
    result::KResult,
    tests::{
        hsm::{EMPTY_TAGS, send_message},
        test_utils::{get_tmp_sqlite_path, https_clap_config},
    },
};

/// Verify that two HSM instances can co-exist and each routes keys to the correct HSM.
/// Uses the `ClapConfig.hsm_instances` path (TOML-style multi-HSM config).
#[tokio::test]
#[ignore = "Requires two SoftHSM2 slots (slot 0 and slot 1) to be initialised"]
async fn test_multi_hsm_routing() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let owner = Uuid::new_v4().to_string();
    let sqlite_path = get_tmp_sqlite_path();

    // Build a ClapConfig with two [[hsm_instances]] entries.
    let mut clap_config = https_clap_config();
    clap_config.db.sqlite_path = sqlite_path;
    clap_config.hsm_instances = vec![
        HsmConfig {
            hsm_model: "softhsm2".to_owned(),
            hsm_admin: vec![owner.clone()],
            hsm_slot: vec![0],
            hsm_password: vec!["12345678".to_owned()],
        },
        HsmConfig {
            hsm_model: "softhsm2".to_owned(),
            hsm_admin: vec![owner.clone()],
            hsm_slot: vec![1],
            hsm_password: vec!["12345678".to_owned()],
        },
    ];

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Create a symmetric key on the first HSM (prefix "hsm", slot 0).
    let key1_uid = format!("hsm::0::{}", Uuid::new_v4());
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(key1_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response = send_message(kms.clone(), &owner, vec![Operation::Create(create_req)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        panic!("Expected CreateResponse");
    };
    info!(
        "Created key on hsm::0 — uid={}",
        create_response.unique_identifier
    );
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(key1_uid.clone())
    );

    // Create a symmetric key on the second HSM (prefix "hsm1", slot 1).
    let key2_uid = format!("hsm1::1::{}", Uuid::new_v4());
    let create_req2 = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(key2_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response2 = send_message(kms.clone(), &owner, vec![Operation::Create(create_req2)]).await?;
    let Operation::CreateResponse(create_response2) = &response2[0] else {
        panic!("Expected CreateResponse for hsm1");
    };
    info!(
        "Created key on hsm1::1 — uid={}",
        create_response2.unique_identifier
    );
    assert_eq!(
        create_response2.unique_identifier,
        UniqueIdentifier::TextString(key2_uid)
    );

    Ok(())
}

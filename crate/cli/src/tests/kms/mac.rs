use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        mac::{CHashingAlgorithm, MacAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_mac() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let mac_key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Sha3,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let large_data = "00".repeat(1024);

    MacAction {
        mac_key_id: mac_key_id.to_string(),
        hashing_algorithm: CHashingAlgorithm::SHA3_256,
        data: Some(large_data),
        correlation_value: None,
        init_indicator: false,
        final_indicator: false,
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{hash::HashAction, mac::CHashingAlgorithm},
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_hash() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    HashAction {
        hashing_algorithm: CHashingAlgorithm::SHA3_256,
        data: Some("010203".to_owned()),
        correlation_value: None,
        init_indicator: false,
        final_indicator: false,
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

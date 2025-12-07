use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::rng::{RngAction, RngCommands},
    error::result::KmsCliResult,
};

#[tokio::test]
pub(super) async fn test_rng_retrieve_and_seed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Retrieve 32 bytes
    let client = ctx.get_owner_client();
    let resp = client
        .rng_retrieve(cosmian_kms_client::kmip_2_1::kmip_operations::RNGRetrieve {
            data_length: 32,
        })
        .await?;

    // Verify the returned data has the correct length
    assert_eq!(
        resp.data.len(),
        32,
        "Expected 32 bytes, but got {}",
        resp.data.len()
    );

    // Seed with 16 zero bytes
    let seed_hex = "00".repeat(16);
    RngAction {
        command: RngCommands::Seed { data: seed_hex },
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

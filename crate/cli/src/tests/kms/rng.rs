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
    RngAction {
        command: RngCommands::Retrieve { length: 32 },
    }
    .run(ctx.get_owner_client())
    .await?;

    // Seed with 16 zero bytes
    let seed_hex = "00".repeat(16);
    RngAction {
        command: RngCommands::Seed { data: seed_hex },
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

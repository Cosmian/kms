use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{actions::kms::actions::KmsActions, error::result::KmsCliResult};

#[tokio::test]
pub(super) async fn test_discover_versions() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Invoke via actions enum path
    KmsActions::DiscoverVersions
        .process(ctx.get_owner_client())
        .await?;

    Ok(())
}

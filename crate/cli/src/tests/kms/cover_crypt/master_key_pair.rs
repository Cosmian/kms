use std::path::PathBuf;

use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::cover_crypt::keys::create_key_pair::CreateMasterKeyPairAction,
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_create_master_key_pair() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    Box::pin(
        CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    Ok(())
}

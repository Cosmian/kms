use test_kms_server::start_default_test_kms_server_with_utimaco_and_kek;

use crate::{
    actions::kms::rsa::keys::create_key_pair::CreateKeyPairAction, error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_rsa_create_key_pair() -> KmsCliResult<()> {
    // from specs
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;

    CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    Ok(())
}

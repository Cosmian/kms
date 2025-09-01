use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::Curve;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::elliptic_curves::keys::create_key_pair::CreateKeyPairAction,
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_create_key_pair() -> KmsCliResult<()> {
    // from specs
    let ctx = start_default_test_kms_server().await;
    CreateKeyPairAction {
        curve: Curve::NistP256,
        tags: vec!["tag1".to_owned(), "tag2".to_owned()],
        private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

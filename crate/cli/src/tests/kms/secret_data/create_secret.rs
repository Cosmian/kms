use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SecretDataType;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::secret_data::create_secret::CreateSecretDataAction, error::result::KmsCliResult,
};

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_create_secret_data() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; 32];

    {
        CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?;
        let _uid = CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?;

        rng.fill_bytes(&mut key);
        let _uid = CreateSecretDataAction {
            secret_value: Some("password".to_owned()),
            secret_type: SecretDataType::Password,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
    }
    Ok(())
}

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::create_key::CreateKeyAction;
use crate::error::result::KmsCliResult;

pub mod create_key;

#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreateKeyAction),
}

impl KeysCommands {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Create(action) => {
                action.run(kms_rest_client).await?;
            }
        }
        Ok(())
    }
}

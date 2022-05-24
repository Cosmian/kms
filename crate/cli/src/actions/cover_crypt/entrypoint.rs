use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;

use super::{
    decrypt::DecryptAction,
    encrypt::EncryptAction,
    keys::{
        DestroyUserKeyAction, NewMasterKeyPairAction, NewUserKeyAction, RevokeUserKeyAction,
        RotateAttributeAction,
    },
};

/// Uses Attribute-Based encryption.
#[derive(StructOpt, Debug)]
pub enum CoverCryptAction {
    Init(NewMasterKeyPairAction),
    Rotate(RotateAttributeAction),

    New(NewUserKeyAction),
    Revoke(RevokeUserKeyAction),
    Destroy(DestroyUserKeyAction),

    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl CoverCryptAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        match self {
            CoverCryptAction::Init(action) => action.run(client_connector).await?,
            CoverCryptAction::Rotate(action) => action.run(client_connector).await?,
            CoverCryptAction::New(action) => action.run(client_connector).await?,
            // For the time being, Revoke an user decryption key is not possible. We dismiss the action in the cli.
            // Uncomment the followings to activate that command.
            CoverCryptAction::Revoke(_) => eyre::bail!("Revokation is not supported yet"), // action.run(client_connector).await?,
            CoverCryptAction::Destroy(action) => action.run(client_connector).await?,
            CoverCryptAction::Encrypt(action) => action.run(client_connector).await?,
            CoverCryptAction::Decrypt(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

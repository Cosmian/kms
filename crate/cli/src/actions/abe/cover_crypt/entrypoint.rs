use clap::StructOpt;
use cosmian_kmip::kmip::kmip_objects::{Object, ObjectType};
use cosmian_kms_client::KmsRestClient;
use eyre::{bail, Context};

use crate::actions::{
    abe::{
        decrypt::DecryptAction,
        encrypt::EncryptAction,
        keys::{
            DestroyUserKeyAction, ExportKeysAction, ImportKeysAction, NewMasterKeyPairAction,
            NewUserKeyAction, RevokeUserKeyAction, RotateAttributeAction,
        },
    },
    kmip_generic::{ExportAction, ImportAction},
};

/// Use CoverCrypt encryption attributes.
#[derive(StructOpt, Debug)]
pub enum CoverCryptAction {
    Init(NewMasterKeyPairAction),
    Rotate(RotateAttributeAction),

    New(NewUserKeyAction),
    Export(ExportAction),
    Import(ImportAction),
    ImportKeys(ImportKeysAction),
    ExportKeys(ExportKeysAction),
    Revoke(RevokeUserKeyAction),
    Destroy(DestroyUserKeyAction),

    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl CoverCryptAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        match self {
            CoverCryptAction::Init(action) => action.run(client_connector, true).await?,
            CoverCryptAction::Rotate(action) => action.run(client_connector, true).await?,
            CoverCryptAction::New(action) => action.run(client_connector, true).await?,
            CoverCryptAction::Export(action) => action.run(client_connector).await?,
            CoverCryptAction::Import(action) => {
                action.run(client_connector, determine_object_type).await?
            }
            CoverCryptAction::ImportKeys(action) => action.run(client_connector, true).await?,
            CoverCryptAction::ExportKeys(action) => action.run(client_connector).await?,
            // For the time being, Revoke an user decryption key is not possible. We dismiss the action in the cli.
            // Uncomment the followings to activate that command.
            CoverCryptAction::Revoke(_) => eyre::bail!("Revocation is not supported yet"), // action.run(client_connector).await?,
            CoverCryptAction::Destroy(action) => action.run(client_connector, true).await?,
            CoverCryptAction::Encrypt(action) => action.run(client_connector).await?,
            CoverCryptAction::Decrypt(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

fn determine_object_type(object: &Object) -> eyre::Result<ObjectType> {
    let key_block = object.key_block().context("Invalid CoverCrypt key block")?;
    Ok(match key_block.key_format_type {
        cosmian_kmip::kmip::kmip_types::KeyFormatType::CoverCryptSecretKey => {
            ObjectType::PrivateKey
        }
        cosmian_kmip::kmip::kmip_types::KeyFormatType::CoverCryptPublicKey => ObjectType::PublicKey,
        x => bail!("Not a CoverCrypt key: {}", x),
    })
}

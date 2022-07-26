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

// Use GPSW encryption attributes
#[derive(StructOpt, Debug)]
pub enum GpswAction {
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

impl GpswAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        match self {
            GpswAction::Init(action) => action.run(client_connector, false).await?,
            GpswAction::Rotate(action) => action.run(client_connector, false).await?,
            GpswAction::New(action) => action.run(client_connector, false).await?,
            GpswAction::Export(action) => action.run(client_connector).await?,
            GpswAction::Import(action) => {
                action.run(client_connector, determine_object_type).await?
            }
            GpswAction::ImportKeys(action) => action.run(client_connector, false).await?,
            GpswAction::ExportKeys(action) => action.run(client_connector).await?,
            // For the time being, Revoke an user decryption key is not possible. We dismiss the action in the cli.
            // Uncomment the followings to activate that command.
            GpswAction::Revoke(_) => eyre::bail!("Revocation is not supported yet"), // action.run(client_connector).await?,
            GpswAction::Destroy(action) => action.run(client_connector, false).await?,
            GpswAction::Encrypt(action) => action.run(client_connector).await?,
            GpswAction::Decrypt(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

fn determine_object_type(object: &Object) -> eyre::Result<ObjectType> {
    let key_block = object.key_block().context("Invalid CoverCrypt key block")?;
    Ok(match key_block.key_format_type {
        cosmian_kmip::kmip::kmip_types::KeyFormatType::AbeMasterSecretKey => ObjectType::PrivateKey,
        cosmian_kmip::kmip::kmip_types::KeyFormatType::AbeMasterPublicKey => ObjectType::PublicKey,
        cosmian_kmip::kmip::kmip_types::KeyFormatType::AbeUserDecryptionKey => {
            ObjectType::PrivateKey
        }
        cosmian_kmip::kmip::kmip_types::KeyFormatType::AbeSymmetricKey => {
            bail!("GPSW ABE Symmetric keys are not supported anymore")
        }
        x => bail!("Not a GPSW key: {x}"),
    })
}

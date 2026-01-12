use std::{fs, path::PathBuf};

use base64::Engine;
use clap::Parser;
use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_data_structures::KeyValue,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, Tag},
    },
};
use cosmian_kms_client::{ExportObjectParams, KmsClient, export_object};
use serde_json::json;

use crate::{
    actions::kms::{attributes::get_attributes, console},
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Wrap a KMS key with an AWS Key Encryption Key (KEK),
/// previously imported using the `cosmian kms aws byok import` command.
/// Generate the `.byok` file that can be used to import the KMS key into AWS KMS.
/// See: <https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html>
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ExportByokAction {
    /// The unique ID of the KMS private key that will be wrapped and then exported
    #[clap(required = true)]
    pub(crate) wrapped_key_id: String,

    /// The AWS KEK ID in this KMS.
    #[clap(required = true)]
    pub(crate) kek_id: String,

    /// The file path to export the `.byok` file to.
    /// If not specified, the file will be called `<wrapped_key_id>.byok`
    #[clap(required = false)]
    pub(crate) byok_file: Option<PathBuf>,
}

impl ExportByokAction {
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<()> {
        Ok(())
    }
}

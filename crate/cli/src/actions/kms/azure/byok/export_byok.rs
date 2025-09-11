use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::kmip_types::Tag;
use cosmian_kms_client::KmsClient;
use crate::actions::kms::attributes::get_attributes;
use crate::error::result::KmsCliResult;

/// Wrap a KMS key with an Azure Key Encryption Key (KEK),
/// previously imported using the `cosmian kms azure byok import` command.
/// Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
/// See: https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ExportByokAction {
    /// The unique ID of the KMS key that will be wrapped
    /// by the Azure KEK key.
    #[clap(required = true)]
    pub(crate) wrapped_key_id: String,

    /// The Azure KEK ID in this KMS.
    #[clap(required = true, verbatim_doc_comment)]
    pub(crate) kek_id: String,

    /// The file path to export the `.byok` file to.
    /// If not specified, the file will be called <wrapped_key_id>.byok
    #[clap(required = false)]
    pub(crate) byok_file: Option<PathBuf>,

}

impl ExportByokAction {
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<()> {
        // Recover the attributes of the KEK key
        let (_uid, _kek_attributes) = get_attributes(
            &kms_client,
            &self.wrapped_key_id,
            &[Tag::Tag],&[]
        ).await?;



        Ok(())
    }
}

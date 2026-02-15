use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
use cosmian_kms_client::{
    KmsClient,
    reexport::cosmian_kms_client_utils::import_utils::{ImportKeyFormat, KeyUsage},
};

use crate::{actions::kms::shared::ImportSecretDataOrKeyAction, error::result::KmsCliResult};

/// Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
/// See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ImportKekAction {
    /// The RSA Key Encryption Key (KEK) file exported from the Azure Key Vault
    /// in PKCS#8 PEM format.
    #[clap(required = true)]
    pub(crate) kek_file: PathBuf,

    /// The Azure Key ID (kid). It should be something like:
    /// <https://mypremiumkeyvault.vault.azure.net/keys/KEK-BYOK/664f5aa2797a4075b8e36ca4500636d8>
    #[clap(required = true, verbatim_doc_comment)]
    pub(crate) kid: String,

    /// The unique ID of the key in this KMS; a random UUID
    /// is generated if not specified.
    #[clap(required = false)]
    pub(crate) key_id: Option<String>,
}

impl ImportKekAction {
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let import_action = ImportSecretDataOrKeyAction {
            key_file: self.kek_file.clone(),
            key_id: self.key_id.clone(),
            key_format: ImportKeyFormat::Pem,
            public_key_id: None,
            private_key_id: None,
            certificate_id: None,
            unwrap: false,
            replace_existing: true,
            tags: vec!["azure".to_owned(), format!("kid:{}", self.kid)],
            key_usage: Some(vec![KeyUsage::WrapKey, KeyUsage::Encrypt]),
            wrapping_key_id: None,
        };

        import_action.run(kms_client).await
    }
}

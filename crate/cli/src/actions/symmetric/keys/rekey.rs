use clap::Parser;
use cosmian_kms_client::{
    kmip::{kmip_operations::ReKey, kmip_types::UniqueIdentifier},
    KmsClient,
};

use crate::{
    actions::console,
    error::result::{CliResult, CliResultHelper},
};

/// Refresh an existing symmetric key
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ReKeyAction {
    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "key-id", short = 'k')]
    key_id: String,
}

impl ReKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let rekey_key_request = ReKey {
            unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
            ..ReKey::default()
        };
        let unique_identifier = kms_rest_client
            .rekey(rekey_key_request)
            .await
            .with_context(|| "failed rekeying the key")?
            .unique_identifier
            .to_string();

        let mut stdout = console::Stdout::new("The symmetric key was successfully refreshed.");
        stdout.set_unique_identifier(unique_identifier);
        stdout.write()?;

        Ok(())
    }
}

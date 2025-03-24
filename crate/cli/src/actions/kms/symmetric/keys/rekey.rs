use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::ReKey, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::{console, kms::labels::KEY_ID},
    error::result::{CosmianResult, CosmianResultHelper},
};

/// Refresh an existing symmetric key
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ReKeyAction {
    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = KEY_ID, short = 'k')]
    key_id: String,
}

impl ReKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
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

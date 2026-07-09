use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::GetAttributes, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Get the automatic rotation policy for a key or key pair.
///
/// Displays: rotation interval, offset, keyset name, generation, and last rotation date.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GetRotationPolicyAction {
    /// The unique identifier of the key to get the rotation policy from.
    #[clap(long = "key-id", short = 'k')]
    key_id: String,
}

impl GetRotationPolicyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(self.key_id.clone());

        let response = kms_rest_client
            .get_attributes(GetAttributes {
                unique_identifier: Some(uid),
                attribute_reference: None,
            })
            .await
            .with_context(|| "failed retrieving attributes")?;

        let attrs = &response.attributes;

        let interval = attrs
            .rotate_interval
            .map_or_else(|| "not set".to_owned(), |v| v.to_string());
        let offset = attrs
            .rotate_offset
            .map_or_else(|| "not set".to_owned(), |v| v.to_string());
        let name = attrs.rotate_name.as_deref().unwrap_or("not set");
        let generation = attrs
            .rotate_generation
            .map_or_else(|| "not set".to_owned(), |v| v.to_string());
        let date = attrs
            .rotate_date
            .map_or_else(|| "never".to_owned(), |d| d.to_string());

        let output = format!(
            "Rotation policy for key: {}\n\
             \x20 Interval (seconds): {interval}\n\
             \x20 Offset (seconds):   {offset}\n\
             \x20 Keyset name:        {name}\n\
             \x20 Generation:         {generation}\n\
             \x20 Last rotation date: {date}",
            response.unique_identifier
        );

        console::Stdout::new(&output).write()?;

        Ok(())
    }
}

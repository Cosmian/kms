use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::GetAttributes, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::{console, labels::KEY_ID},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Display the rotation policy of a symmetric key.
///
/// Shows the rotation attributes currently set on the key:
///   • `RotateInterval`   — rotation period in seconds (0 = disabled)
///   • `RotateName`       — human-readable label
///   • `RotateOffset`     — offset from Initial Date
///   • `RotateGeneration` — number of rotations performed
///   • `RotateDate`       — timestamp of the last rotation
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct GetRotationPolicyAction {
    /// The unique identifier or tag of the key to inspect.
    #[clap(long = KEY_ID, short = 'k')]
    key_id: String,
}

impl GetRotationPolicyAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
            attribute_reference: None,
        };
        let response = kms_rest_client
            .get_attributes(request)
            .await
            .with_context(|| "failed retrieving attributes")?;

        let attrs = &response.attributes;

        let interval = attrs.rotate_interval.unwrap_or(0);
        let offset = attrs.rotate_offset.unwrap_or(0);
        let generation = attrs.rotate_generation.unwrap_or(0);
        let name = attrs.rotate_name.as_deref().unwrap_or("(none)");
        let date = attrs
            .rotate_date
            .map_or_else(|| "(never)".to_owned(), |d| d.to_string());

        let status = if interval == 0 { "disabled" } else { "enabled" };

        let message = format!(
            "Rotation policy for {}:\n\
             \n\
             Status     : {status}\n\
             Interval   : {interval} seconds\n\
             Offset     : {offset} seconds\n\
             Name       : {name}\n\
             Generation : {generation}\n\
             Last rotated: {date}",
            self.key_id,
        );

        let stdout = console::Stdout::new(&message);
        stdout.write()?;

        Ok(())
    }
}

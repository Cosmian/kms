use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute, kmip_operations::SetAttribute, kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Set the automatic rotation policy on a key or key pair.
///
/// This configures:
///  - The rotation interval (how often the key is automatically re-keyed)
///  - An optional offset (delay before first rotation)
///  - An optional keyset name (for addressing key generations via name@version syntax)
///
/// At least one of --interval or --rotation-name must be provided.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SetRotationPolicyAction {
    /// The unique identifier of the key to set the rotation policy on.
    #[clap(long = "key-id", short = 'k')]
    key_id: String,

    /// Rotation interval in seconds. The key will be automatically re-keyed at this interval.
    /// Set to 0 to disable automatic rotation while preserving other policy fields.
    #[clap(long = "interval", short = 'i')]
    interval_secs: Option<i64>,

    /// Offset in seconds from the initial date before the first rotation occurs.
    #[clap(long = "offset", short = 'o')]
    offset_secs: Option<i64>,

    /// A keyset name for addressing key generations via name@latest, name@first, name@N syntax.
    /// Must not contain the '@' character.
    #[clap(long = "rotation-name", short = 'n')]
    rotate_name: Option<String>,
}

impl SetRotationPolicyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(self.key_id.clone());

        // Set the rotation interval if provided
        if let Some(interval) = self.interval_secs {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateInterval(interval),
                })
                .await
                .with_context(|| "failed setting RotateInterval attribute")?;
        }

        // Set the rotation offset if provided
        if let Some(offset) = self.offset_secs {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateOffset(offset),
                })
                .await
                .with_context(|| "failed setting RotateOffset attribute")?;
        }

        // Set the rotation name if provided
        if let Some(ref name) = self.rotate_name {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateName(name.clone()),
                })
                .await
                .with_context(|| "failed setting RotateName attribute")?;
        }

        let mut stdout = console::Stdout::new("Rotation policy set successfully.");
        stdout.set_unique_identifier(&uid);
        stdout.write()?;

        Ok(())
    }
}

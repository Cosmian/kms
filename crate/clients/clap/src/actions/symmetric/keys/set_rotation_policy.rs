use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute, kmip_operations::SetAttribute, kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::{console, labels::KEY_ID},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Set the rotation policy for a symmetric key.
///
/// Use this command to configure automated key rotation by setting the
/// rotation interval. Once the interval is set, the KMS background task
/// will automatically rotate the key when it is due.
///
/// Setting `--interval` to 0 disables automatic rotation for the key.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct SetRotationPolicyAction {
    /// The unique identifier of the key to configure.
    #[clap(long = KEY_ID, short = 'k')]
    pub(crate) key_id: String,

    /// Rotation interval in seconds. Set to 0 to disable auto-rotation.
    /// Example: 86400 for daily rotation, 604800 for weekly.
    #[clap(long, short = 'i')]
    pub(crate) interval: Option<i32>,

    /// The name used to track the rotation lineage (optional).
    #[clap(long, short = 'n')]
    pub(crate) name: Option<String>,

    /// Time offset in seconds from the creation date before the first rotation
    /// is triggered (optional). Defaults to the interval if not set.
    #[clap(long)]
    pub(crate) offset: Option<i32>,
}

impl SetRotationPolicyAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(self.key_id.clone());
        let mut updated = vec![];

        if let Some(interval) = self.interval {
            let req = SetAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: Attribute::RotateInterval(interval),
            };
            kms_rest_client
                .set_attribute(req)
                .await
                .with_context(|| "failed to set RotateInterval")?;
            updated.push(format!("interval={interval}s"));
        }

        if let Some(ref name) = self.name {
            let req = SetAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: Attribute::RotateName(name.clone()),
            };
            kms_rest_client
                .set_attribute(req)
                .await
                .with_context(|| "failed to set RotateName")?;
            updated.push(format!("name={name}"));
        }

        if let Some(offset) = self.offset {
            let req = SetAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: Attribute::RotateOffset(offset),
            };
            kms_rest_client
                .set_attribute(req)
                .await
                .with_context(|| "failed to set RotateOffset")?;
            updated.push(format!("offset={offset}s"));
        }

        if updated.is_empty() {
            let stdout = console::Stdout::new(
                "No rotation policy attributes specified. Use --interval, --name, or --offset.",
            );
            stdout.write()?;
        } else {
            let msg = format!(
                "Rotation policy updated for key {}: {}",
                self.key_id,
                updated.join(", ")
            );
            let stdout = console::Stdout::new(&msg);
            stdout.write()?;
        }

        Ok(())
    }
}

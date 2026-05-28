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

/// Set a rotation policy on a symmetric key.
///
/// The rotation policy controls automatic key rotation by the server's
/// background scheduler.  Setting `--interval 0` disables auto-rotation.
///
/// Attributes set:
///   • `RotateInterval`  — rotation period in seconds
///   • `RotateName`      — optional human-readable label
///   • `RotateOffset`    — offset from Initial Date for the first rotation
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct SetRotationPolicyAction {
    /// The unique identifier or tag of the key to configure.
    #[clap(long = KEY_ID, short = 'k')]
    key_id: String,

    /// Rotation interval in seconds.  Use `0` to disable auto-rotation.
    #[clap(long)]
    interval: i32,

    /// Optional human-readable label for this rotation policy (e.g. "hourly", "daily").
    #[clap(long)]
    name: Option<String>,

    /// Offset in seconds from the key's Initial Date before the first rotation triggers.
    #[clap(long, default_value = "0")]
    offset: i32,
}

impl SetRotationPolicyAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(self.key_id.clone());

        // Set RotateInterval
        kms_rest_client
            .set_attribute(SetAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: Attribute::RotateInterval(self.interval),
            })
            .await
            .with_context(|| "failed setting RotateInterval")?;

        // Set RotateOffset
        kms_rest_client
            .set_attribute(SetAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: Attribute::RotateOffset(self.offset),
            })
            .await
            .with_context(|| "failed setting RotateOffset")?;

        // Set RotateName if provided
        if let Some(ref name) = self.name {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateName(name.clone()),
                })
                .await
                .with_context(|| "failed setting RotateName")?;
        }

        let mut stdout = console::Stdout::new("Rotation policy has been set.");
        stdout.set_unique_identifier(&uid);
        stdout.write()?;

        Ok(())
    }
}
